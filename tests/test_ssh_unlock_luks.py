import email
import email.policy
import http.client
import socket
import urllib.error
from types import SimpleNamespace

import pytest
from loguru import logger
from paramiko import AutoAddPolicy, RejectPolicy

import ssh_unlock_luks as sul
from ssh_unlock_luks import Config

ENV_VARS = (
    "SUL_SSH_IP",
    "SUL_SSH_PORT",
    "SUL_PROD_SSH_PORT",
    "SUL_LUKS_PASS",
    "SUL_SSH_USER",
    "SUL_SSH_KEY",
    "SUL_CONTROL_CSV_URL",
    "SUL_ALLOW_UNKNOWN_HOST",
    "SUL_MAIL_TO",
    "SUL_MAIL_FROM",
    "SUL_MAIL_SUBJECT",
    "SUL_DOWN_ALARM_MINUTES",
    "SUL_STATE_FILE",
)


# --------------------------------------------------------------------------- shared fixtures


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for name in ENV_VARS:
        monkeypatch.delenv(name, raising=False)


@pytest.fixture(autouse=True)
def reset_logger():
    yield
    # setup_logging() binds a sink to the (captured) stdout; drop it so it cannot outlive the test
    logger.remove()


@pytest.fixture
def cfg(monkeypatch, tmp_path) -> Config:
    monkeypatch.setenv("SUL_SSH_IP", "192.0.2.1")
    monkeypatch.setenv("SUL_SSH_PORT", "22")
    monkeypatch.setenv("SUL_PROD_SSH_PORT", "22")
    monkeypatch.setenv("SUL_LUKS_PASS", "s3cret")
    monkeypatch.setenv("SUL_MAIL_TO", "to@example.com")
    monkeypatch.setenv("SUL_STATE_FILE", str(tmp_path / "state" / "state.json"))
    return Config(_env_file=None)


# --------------------------------------------------------------------------- test doubles


class FakeClock:
    """Deterministic replacement for `monotonic` and `sleep`."""

    def __init__(self):
        self.now = 0.0
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


@pytest.fixture
def clock(monkeypatch) -> FakeClock:
    fake = FakeClock()
    monkeypatch.setattr(sul, "monotonic", fake.monotonic)
    monkeypatch.setattr(sul, "sleep", fake.sleep)
    return fake


class FakeSocket:
    """Context-manager socket stub returning a canned banner."""

    def __init__(self, data: bytes = b""):
        self.data = data
        self.timeout = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def settimeout(self, timeout):
        self.timeout = timeout

    def recv(self, size):
        return self.data[:size]


class FakeResponse:
    def __init__(self, text: str = "", error: Exception | None = None):
        self.body = text.encode()
        self.error = error

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def read(self, size=-1):
        return self.body if size < 0 else self.body[:size]


class FakeSSHClient:
    """Records the host key configuration instead of touching the network or disk."""

    def __init__(self):
        self.loaded_host_keys: str | None = None
        self.policy = None

    def load_host_keys(self, filename):
        self.loaded_host_keys = filename

    def set_missing_host_key_policy(self, policy):
        self.policy = policy


class FakeChannel:
    def __init__(self, recv_ready=True, send_ready=True, closed=True):
        self._recv_ready = recv_ready
        self._send_ready = send_ready
        self.closed = closed
        self.sent: list[bytes] = []
        self.timeout = None

    def settimeout(self, timeout):
        self.timeout = timeout

    def recv_ready(self):
        return self._recv_ready

    def send_ready(self):
        return self._send_ready

    def exit_status_ready(self):
        return False

    def recv(self, size):
        return b"prompt"

    def send(self, data):
        self.sent.append(data)
        return len(data)


class FakeConnectedClient:
    def __init__(self, channel: FakeChannel):
        self.channel = channel
        self.connect_kwargs: dict = {}
        self.exited = False

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.exited = True
        return False

    def connect(self, **kwargs):
        self.connect_kwargs = kwargs

    def invoke_shell(self):
        return self.channel


# --------------------------------------------------------------------------- tests


class TestWaitFor:
    def test_returns_immediately_if_true(self, clock):
        assert sul.wait_for(lambda: True, timeout=5) is True
        assert clock.sleeps == []

    def test_polls_until_true(self, clock):
        calls = iter([False, False, True])
        assert sul.wait_for(lambda: next(calls), timeout=5, interval=0.5) is True
        assert clock.sleeps == [0.5, 0.5]

    def test_times_out(self, clock):
        assert sul.wait_for(lambda: False, timeout=2, interval=0.5) is False
        assert sum(clock.sleeps) == pytest.approx(2)


class TestIsPortOpen:
    def test_true_on_successful_connect(self, monkeypatch):
        seen = {}

        def fake_connect(address, timeout):
            seen.update(address=address, timeout=timeout)
            return FakeSocket()

        monkeypatch.setattr(socket, "create_connection", fake_connect)
        assert sul.is_port_open("192.0.2.1", 22, timeout=0.3) is True
        assert seen == {"address": ("192.0.2.1", 22), "timeout": 0.3}

    @pytest.mark.parametrize("exc", [ConnectionRefusedError, TimeoutError, OSError])
    def test_false_on_oserror(self, monkeypatch, exc):
        def fake_connect(*_args, **_kwargs):
            raise exc

        monkeypatch.setattr(socket, "create_connection", fake_connect)
        assert sul.is_port_open("192.0.2.1", 22) is False


class TestReadBanner:
    def test_returns_data(self, monkeypatch):
        monkeypatch.setattr(socket, "create_connection", lambda *_a, **_kw: FakeSocket(b"SSH-2.0-dropbear_2022.83\r\n"))
        assert sul.read_banner("192.0.2.1", 22) == b"SSH-2.0-dropbear_2022.83\r\n"

    @pytest.mark.parametrize("exc", [TimeoutError, ConnectionRefusedError, OSError("boom")])
    def test_returns_none_on_errors(self, monkeypatch, exc):
        def fake_connect(*_args, **_kwargs):
            raise exc

        monkeypatch.setattr(socket, "create_connection", fake_connect)
        assert sul.read_banner("192.0.2.1", 22) is None

    def test_returns_none_on_recv_timeout(self, monkeypatch):
        class TimeoutSocket(FakeSocket):
            def recv(self, size):
                raise TimeoutError

        monkeypatch.setattr(socket, "create_connection", lambda *_a, **_kw: TimeoutSocket())
        assert sul.read_banner("192.0.2.1", 22) is None


class TestUnlockAllowedByControlServer:
    @staticmethod
    def patch_get(monkeypatch, response: FakeResponse) -> dict:
        seen: dict = {}

        def fake_urlopen(url, timeout):
            seen.update(url=url, timeout=timeout)
            if response.error:
                raise response.error
            return response

        monkeypatch.setattr(sul.urllib.request, "urlopen", fake_urlopen)
        return seen

    @pytest.mark.parametrize("flag", ["yes", "YES", "1", "true", " True "])
    def test_allows_truthy_flags(self, monkeypatch, cfg, flag):
        seen = self.patch_get(monkeypatch, FakeResponse(f"192.0.2.1,{flag}\n"))
        monkeypatch.setenv("SUL_CONTROL_CSV_URL", "https://example.invalid/control.csv")
        assert sul.unlock_allowed_by_control_server(Config(_env_file=None)) is sul.Decision.ALLOW
        assert seen == {
            "url": "https://example.invalid/control.csv",
            "timeout": 5,
        }

    @pytest.mark.parametrize("flag", ["yes!", "YES!", " yes! "])
    def test_force_flag(self, monkeypatch, cfg, flag):
        self.patch_get(monkeypatch, FakeResponse(f"192.0.2.1,{flag}\n"))
        assert sul.unlock_allowed_by_control_server(cfg) is sul.Decision.FORCE

    @pytest.mark.parametrize("flag", ["no", "0", "false", ""])
    def test_denies_other_flags(self, monkeypatch, cfg, flag):
        self.patch_get(monkeypatch, FakeResponse(f"192.0.2.1,{flag}\n"))
        assert sul.unlock_allowed_by_control_server(cfg) is sul.Decision.DENY

    def test_denies_unlisted_host(self, monkeypatch, cfg):
        self.patch_get(monkeypatch, FakeResponse("192.0.2.99,yes\n"))
        assert sul.unlock_allowed_by_control_server(cfg) is sul.Decision.DENY

    def test_skips_malformed_rows_and_finds_host(self, monkeypatch, cfg):
        csv_text = "\nonlyonecolumn\n192.0.2.99,yes\n  192.0.2.1 , yes \n"
        self.patch_get(monkeypatch, FakeResponse(csv_text))
        assert sul.unlock_allowed_by_control_server(cfg) is sul.Decision.ALLOW

    def test_empty_body(self, monkeypatch, cfg):
        self.patch_get(monkeypatch, FakeResponse(""))
        assert sul.unlock_allowed_by_control_server(cfg) is sul.Decision.DENY

    def test_limits_body_size(self, monkeypatch, cfg):
        monkeypatch.setattr(sul, "MAX_CSV_BYTES", 10)
        self.patch_get(monkeypatch, FakeResponse("192.0.2.99,no\n192.0.2.1,yes\n"))
        assert sul.unlock_allowed_by_control_server(cfg) is sul.Decision.DENY

    @pytest.mark.parametrize(
        "error",
        [
            urllib.error.HTTPError("https://example.invalid", 503, "unavailable", email.message.Message(), None),
            urllib.error.URLError("down"),
            http.client.IncompleteRead(b""),
        ],
    )
    def test_propagates_fetch_errors(self, monkeypatch, cfg, error):
        self.patch_get(monkeypatch, FakeResponse(error=error))
        with pytest.raises(sul.FETCH_ERRORS):
            sul.unlock_allowed_by_control_server(cfg)


class TestCreateSshClient:
    @pytest.fixture(autouse=True)
    def script_dir(self, monkeypatch, tmp_path):
        """Point the module's `__file__` to a temp dir so `host_keys` is looked up there."""
        monkeypatch.setattr(sul, "__file__", str(tmp_path / "ssh_unlock_luks.py"))
        monkeypatch.setattr(sul, "SSHClient", FakeSSHClient)
        return tmp_path

    def test_with_host_keys_rejects_unknown(self, script_dir, cfg):
        host_keys = script_dir / "host_keys"
        host_keys.write_text("")
        client = sul.create_ssh_client(cfg)
        assert client.loaded_host_keys == str(host_keys)
        assert isinstance(client.policy, RejectPolicy)

    def test_host_keys_win_over_allow_unknown(self, script_dir, monkeypatch, cfg):
        (script_dir / "host_keys").write_text("")
        monkeypatch.setenv("SUL_ALLOW_UNKNOWN_HOST", "1")
        client = sul.create_ssh_client(Config(_env_file=None))
        assert isinstance(client.policy, RejectPolicy)

    def test_fails_closed_without_host_keys(self, cfg):
        with pytest.raises(FileNotFoundError, match="SUL_ALLOW_UNKNOWN_HOST"):
            sul.create_ssh_client(cfg)

    def test_allow_unknown_host(self, monkeypatch, cfg):
        monkeypatch.setenv("SUL_ALLOW_UNKNOWN_HOST", "1")
        client = sul.create_ssh_client(Config(_env_file=None))
        assert client.loaded_host_keys is None
        assert isinstance(client.policy, AutoAddPolicy)


class TestSendPassphrase:
    @pytest.fixture
    def ssh(self, monkeypatch, clock) -> FakeConnectedClient:
        client = FakeConnectedClient(FakeChannel())
        monkeypatch.setattr(sul, "create_ssh_client", lambda _cfg: client)
        return client

    def test_sends_secret_with_newline(self, ssh, cfg):
        sul.send_passphrase(cfg)
        assert ssh.channel.sent == [b"s3cret\n"]
        assert ssh.exited is True

    def test_connect_arguments(self, ssh, monkeypatch, tmp_path):
        key_file = tmp_path / "id_ed25519"
        key_file.write_text("")
        monkeypatch.setenv("SUL_SSH_IP", "192.0.2.1")
        monkeypatch.setenv("SUL_SSH_PORT", "22")
        monkeypatch.setenv("SUL_PROD_SSH_PORT", "22")
        monkeypatch.setenv("SUL_LUKS_PASS", "s3cret")
        monkeypatch.setenv("SUL_MAIL_TO", "to@example.com")
        monkeypatch.setenv("SUL_SSH_USER", "unlock")
        monkeypatch.setenv("SUL_SSH_KEY", str(key_file))
        sul.send_passphrase(Config(_env_file=None))
        assert ssh.connect_kwargs == {
            "hostname": "192.0.2.1",
            "port": 22,
            "username": "unlock",
            "key_filename": str(key_file),
            "timeout": 10,
            "banner_timeout": 10,
        }

    def test_raises_if_not_receive_ready(self, ssh, cfg):
        ssh.channel._recv_ready = False
        with pytest.raises(TimeoutError, match="receive-ready"):
            sul.send_passphrase(cfg)
        assert ssh.channel.sent == []

    def test_raises_if_not_send_ready(self, ssh, cfg):
        ssh.channel._send_ready = False
        with pytest.raises(TimeoutError, match="send-ready"):
            sul.send_passphrase(cfg)
        assert ssh.channel.sent == []

    def test_waits_settle_time_if_channel_stays_open(self, ssh, clock, cfg):
        ssh.channel.closed = False
        sul.send_passphrase(cfg)  # must not raise: the verdict comes from verify_unlock
        assert clock.now >= sul.SETTLE_SECONDS

    def test_does_not_wait_if_channel_closed(self, ssh, clock, cfg):
        sul.send_passphrase(cfg)
        assert clock.now == 0

    def test_propagates_connect_errors(self, ssh, cfg):
        def failing_connect(**_kwargs):
            raise OSError("unreachable")

        ssh.connect = failing_connect
        with pytest.raises(OSError, match="unreachable"):
            sul.send_passphrase(cfg)
        assert ssh.exited is True


class TestEvaluateUnlock:
    @pytest.mark.parametrize(
        ("dropbear_open", "prod_open", "expected"),
        [
            (True, True, sul.UnlockState.UNLOCKED),
            (False, True, sul.UnlockState.UNLOCKED),
            (False, False, sul.UnlockState.BOOTING),
            (True, False, sul.UnlockState.PENDING),
        ],
    )
    def test_rules(self, dropbear_open, prod_open, expected):
        assert sul.evaluate_unlock(dropbear_open=dropbear_open, prod_open=prod_open) == expected


class TestVerifyUnlock:
    @pytest.fixture
    def cfg(self, cfg, monkeypatch):
        monkeypatch.setenv("SUL_SSH_PORT", "2222")
        monkeypatch.setenv("SUL_PROD_SSH_PORT", "22")
        monkeypatch.setenv("SUL_VERIFY_SECONDS", "10")
        return Config(_env_file=None)

    @staticmethod
    def patch_ports(monkeypatch, *, dropbear, prod):
        """`dropbear` / `prod` are callables returning the port state at the current poll."""
        ports = {2222: dropbear, 22: prod}
        monkeypatch.setattr(sul, "is_port_open", lambda _host, port, timeout=1.0: ports[port]())

    def test_returns_when_prod_port_opens(self, monkeypatch, clock, cfg):
        self.patch_ports(monkeypatch, dropbear=lambda: False, prod=lambda: clock.now >= 4)
        sul.verify_unlock(cfg)
        assert 4 <= clock.now < 10

    def test_succeeds_immediately_if_prod_open(self, monkeypatch, clock, cfg):
        self.patch_ports(monkeypatch, dropbear=lambda: False, prod=lambda: True)
        sul.verify_unlock(cfg)
        assert clock.now == 0

    def test_rejected_passphrase(self, monkeypatch, clock, cfg):
        self.patch_ports(monkeypatch, dropbear=lambda: True, prod=lambda: False)
        with pytest.raises(RuntimeError, match="not accepted"):
            sul.verify_unlock(cfg)
        assert clock.now >= 10

    def test_boot_too_slow(self, monkeypatch, clock, cfg):
        self.patch_ports(monkeypatch, dropbear=lambda: False, prod=lambda: False)
        with pytest.raises(RuntimeError, match="not reachable within 10 s"):
            sul.verify_unlock(cfg)
        assert clock.now >= 10


class TestNotify:
    @pytest.fixture
    def run_calls(self, monkeypatch):
        calls = []

        def fake_run(args, input, check, timeout, capture_output=False):
            calls.append(SimpleNamespace(args=args, input=input, check=check, timeout=timeout))
            return SimpleNamespace(stderr=b"")

        monkeypatch.setattr(sul.subprocess, "run", fake_run)
        monkeypatch.setattr(sul.shutil, "which", lambda _name: "/usr/bin/sendmail")
        return calls

    def test_builds_message_with_headers(self, monkeypatch, cfg, run_calls):
        monkeypatch.setenv("SUL_MAIL_FROM", "from@example.com")
        sul.notify(Config(_env_file=None), success=True, detail="all good")
        sent = email.message_from_bytes(run_calls[0].input, policy=email.policy.default)
        assert sent["To"] == "to@example.com"
        assert sent["From"] == "from@example.com"
        assert "SUCCESS" in sent["Subject"]
        assert "192.0.2.1" in sent["Subject"]
        assert "all good" in sent.get_content()

    def test_omits_from_header_if_unset(self, cfg, run_calls):
        sul.notify(cfg, success=True, detail="ok")
        sent = email.message_from_bytes(run_calls[0].input)
        assert sent["From"] is None

    def test_failure_marks_subject_as_failure(self, cfg, run_calls):
        sul.notify(cfg, success=False, detail="boom")
        sent = email.message_from_bytes(run_calls[0].input, policy=email.policy.default)
        assert "FAILURE" in sent["Subject"]
        assert "boom" in sent.get_content()

    def test_invokes_sendmail_with_explicit_recipient(self, cfg, run_calls):
        sul.notify(cfg, success=True, detail="ok")
        assert run_calls[0].args == ["/usr/bin/sendmail", "-oi", "--", "to@example.com"]

    def test_message_has_date_and_message_id(self, cfg, run_calls):
        sul.notify(cfg, success=True, detail="ok")
        sent = email.message_from_bytes(run_calls[0].input, policy=email.policy.default)
        assert sent["Date"]
        assert sent["Message-ID"]

    def test_falls_back_to_default_sendmail_path(self, monkeypatch, cfg, run_calls):
        monkeypatch.setattr(sul.shutil, "which", lambda _name: None)
        sul.notify(cfg, success=True, detail="ok")
        assert run_calls[0].args[0] == sul.SENDMAIL_FALLBACK

    def test_logs_warning_and_does_not_raise_on_missing_binary(self, monkeypatch, cfg, capsys):
        def fake_run(*_args, **_kwargs):
            raise FileNotFoundError("sendmail")

        monkeypatch.setattr(sul.subprocess, "run", fake_run)
        monkeypatch.setattr(sul.shutil, "which", lambda _name: "/usr/bin/sendmail")
        sul.setup_logging(verbose=False)
        sul.notify(cfg, success=True, detail="ok")
        assert "Failed to send notification email" in capsys.readouterr().out

    def test_logs_warning_and_does_not_raise_on_nonzero_exit(self, monkeypatch, cfg, capsys):
        def fake_run(*_args, **_kwargs):
            raise sul.subprocess.CalledProcessError(1, ["sendmail"])

        monkeypatch.setattr(sul.subprocess, "run", fake_run)
        monkeypatch.setattr(sul.shutil, "which", lambda _name: "/usr/bin/sendmail")
        sul.setup_logging(verbose=False)
        sul.notify(cfg, success=True, detail="ok")
        assert "Failed to send notification email" in capsys.readouterr().out

    @pytest.fixture
    def redirect_tmp_dir(self, monkeypatch, tmp_path):
        """Redirect notify()'s hardcoded `/tmp` to a throwaway test directory."""
        real_named_temp_file = sul.tempfile.NamedTemporaryFile

        def fake_named_temp_file(*, mode, dir, prefix, suffix, delete):
            del dir
            return real_named_temp_file(mode=mode, dir=str(tmp_path), prefix=prefix, suffix=suffix, delete=delete)

        monkeypatch.setattr(sul.tempfile, "NamedTemporaryFile", fake_named_temp_file)
        return tmp_path

    def test_dry_run_does_not_invoke_sendmail(self, cfg, run_calls, redirect_tmp_dir):
        sul.notify(cfg, success=True, detail="ok", dry_run=True)
        assert run_calls == []

    def test_dry_run_logs_the_message(self, cfg, run_calls, redirect_tmp_dir, capsys):
        sul.setup_logging(verbose=False)
        sul.notify(cfg, success=True, detail="all good", dry_run=True)
        out = capsys.readouterr().out
        assert "To: to@example.com" in out
        assert "all good" in out

    def test_dry_run_saves_message_to_file(self, cfg, run_calls, redirect_tmp_dir, capsys):
        tmp_path = redirect_tmp_dir
        sul.setup_logging(verbose=False)
        sul.notify(cfg, success=False, detail="boom", dry_run=True)
        saved = list(tmp_path.glob("ssh_unlock_luks_mail_*.eml"))
        assert len(saved) == 1
        content = saved[0].read_text()
        assert "FAILURE" in content
        assert "boom" in content
        assert str(saved[0]) in capsys.readouterr().out


class TestSendMail:
    def test_dry_run_previews_message_without_sending(self, cfg, monkeypatch, tmp_path, capsys):
        monkeypatch.setattr(sul.subprocess, "run", lambda *a, **k: pytest.fail("must not send"))
        real = sul.tempfile.NamedTemporaryFile
        monkeypatch.setattr(
            sul.tempfile,
            "NamedTemporaryFile",
            lambda *, mode, dir, prefix, suffix, delete: real(
                mode=mode, dir=str(tmp_path), prefix=prefix, suffix=suffix, delete=delete
            ),
        )
        sul.setup_logging(verbose=False)
        sul.send_mail(cfg, "subj", "body-text", dry_run=True)
        out = capsys.readouterr().out
        assert "Subject: subj" in out
        assert "body-text" in out


class TestLoadSaveState:
    def test_missing_file_yields_empty_state(self, tmp_path):
        assert sul.load_state(tmp_path / "nope.json") == {}

    def test_roundtrip(self, tmp_path):
        path = tmp_path / "dir" / "state.json"
        sul.save_state(path, {"down_since": 1.5, "alarm_sent": True})
        assert sul.load_state(path) == {"down_since": 1.5, "alarm_sent": True}

    def test_corrupt_file_yields_empty_state(self, tmp_path, capsys):
        path = tmp_path / "state.json"
        path.write_text("{not json")
        sul.setup_logging(verbose=False)
        assert sul.load_state(path) == {}
        assert "unreadable state file" in capsys.readouterr().out

    def test_non_dict_json_yields_empty_state(self, tmp_path):
        path = tmp_path / "state.json"
        path.write_text("[1, 2]")
        assert sul.load_state(path) == {}

    def test_empty_state_removes_file(self, tmp_path):
        path = tmp_path / "state.json"
        sul.save_state(path, {"down_since": 1.0})
        sul.save_state(path, {})
        assert not path.exists()

    def test_write_error_is_only_logged(self, monkeypatch, tmp_path, capsys):
        def fail(*_args, **_kwargs):
            raise OSError("disk full")  # noqa: TRY003

        monkeypatch.setattr(sul.Path, "write_text", fail)
        sul.setup_logging(verbose=False)
        sul.save_state(tmp_path / "state.json", {"down_since": 1.0})
        assert "Failed to write state file" in capsys.readouterr().out


class TestCheckDowntime:
    @pytest.fixture
    def alarm_cfg(self, monkeypatch, cfg) -> Config:
        monkeypatch.setenv("SUL_DOWN_ALARM_MINUTES", "10")
        return Config(_env_file=None)

    @pytest.fixture
    def mails(self, monkeypatch):
        sent = []
        monkeypatch.setattr(
            sul, "send_mail", lambda _cfg, subject, body, *, dry_run=False: sent.append((subject, body, dry_run))
        )
        return sent

    def test_disabled_does_nothing(self, cfg, mails):
        sul.check_downtime(cfg, False, now=1000.0)
        assert mails == []
        assert not cfg.state_file.exists()

    def test_first_closed_run_records_start_without_alarm(self, alarm_cfg, mails):
        sul.check_downtime(alarm_cfg, False, now=1000.0)
        assert mails == []
        assert sul.load_state(alarm_cfg.state_file) == {"down_since": 1000.0, "alarm_sent": False}

    def test_below_threshold_no_alarm(self, alarm_cfg, mails):
        sul.check_downtime(alarm_cfg, False, now=1000.0)
        sul.check_downtime(alarm_cfg, False, now=1000.0 + 9 * 60)
        assert mails == []

    def test_alarm_sent_once_after_threshold(self, alarm_cfg, mails):
        sul.check_downtime(alarm_cfg, False, now=1000.0)
        sul.check_downtime(alarm_cfg, False, now=1000.0 + 10 * 60)
        sul.check_downtime(alarm_cfg, False, now=1000.0 + 20 * 60)
        assert len(mails) == 1
        subject, _body, dry_run = mails[0]
        assert "closed for 10 min" in subject
        assert dry_run is False
        assert sul.load_state(alarm_cfg.state_file)["alarm_sent"] is True

    def test_alarm_mail_contains_reboot_rule(self, alarm_cfg, mails):
        sul.check_downtime(alarm_cfg, False, now=1000.0)
        sul.check_downtime(alarm_cfg, False, now=1000.0 + 15 * 60)
        body = mails[0][1]
        assert "do NOT arm/unlock automatically" in body
        assert "Provider console" in body
        assert "Logs" in body

    def test_recovery_after_alarm_sends_notice_and_clears_state(self, alarm_cfg, mails):
        sul.check_downtime(alarm_cfg, False, now=1000.0)
        sul.check_downtime(alarm_cfg, False, now=1000.0 + 12 * 60)
        mails.clear()
        sul.check_downtime(alarm_cfg, True, now=1000.0 + 30 * 60)
        assert len(mails) == 1
        assert "reachable again" in mails[0][0]
        assert "30 min" in mails[0][1]
        assert sul.load_state(alarm_cfg.state_file) == {"last_seen_open": 1000.0 + 30 * 60}

    def test_recovery_without_alarm_is_silent_and_resets_outage(self, alarm_cfg, mails):
        sul.check_downtime(alarm_cfg, False, now=1000.0)
        sul.check_downtime(alarm_cfg, True, now=1000.0 + 60)
        assert mails == []
        assert sul.load_state(alarm_cfg.state_file) == {"last_seen_open": 1000.0 + 60}

    def test_open_port_records_last_seen(self, alarm_cfg, mails):
        sul.check_downtime(alarm_cfg, True, now=1000.0)
        assert mails == []
        assert sul.load_state(alarm_cfg.state_file) == {"last_seen_open": 1000.0}

    def test_open_port_dry_run_writes_no_state(self, alarm_cfg, mails):
        sul.check_downtime(alarm_cfg, True, dry_run=True, now=1000.0)
        assert not alarm_cfg.state_file.exists()

    def test_closed_port_keeps_last_seen(self, alarm_cfg, mails):
        sul.check_downtime(alarm_cfg, True, now=1000.0)
        sul.check_downtime(alarm_cfg, False, now=1060.0)
        assert sul.load_state(alarm_cfg.state_file) == {
            "last_seen_open": 1000.0,
            "down_since": 1060.0,
            "alarm_sent": False,
        }

    def test_tracking_works_without_down_alarm(self, monkeypatch, cfg, mails):
        monkeypatch.setenv("SUL_UNLOCK_MAX_DOWN_MINUTES", "15")
        limit_cfg = Config(_env_file=None)
        sul.check_downtime(limit_cfg, True, now=1000.0)
        sul.check_downtime(limit_cfg, False, now=1000.0 + 3600)
        assert mails == []
        assert sul.load_state(limit_cfg.state_file)["last_seen_open"] == 1000.0

    def test_new_outage_after_recovery_alarms_again(self, alarm_cfg, mails):
        for start in (1000.0, 100000.0):
            sul.check_downtime(alarm_cfg, False, now=start)
            sul.check_downtime(alarm_cfg, False, now=start + 11 * 60)
            sul.check_downtime(alarm_cfg, True, now=start + 12 * 60)
        assert len([m for m in mails if "closed for" in m[0]]) == 2

    def test_dry_run_previews_mail_but_writes_no_state(self, alarm_cfg, mails):
        sul.save_state(alarm_cfg.state_file, {"down_since": 1000.0, "alarm_sent": False})
        sul.check_downtime(alarm_cfg, False, dry_run=True, now=1000.0 + 11 * 60)
        assert len(mails) == 1
        assert mails[0][2] is True
        assert sul.load_state(alarm_cfg.state_file) == {"down_since": 1000.0, "alarm_sent": False}

    def test_dry_run_first_closed_run_writes_no_state(self, alarm_cfg, mails):
        sul.check_downtime(alarm_cfg, False, dry_run=True, now=1000.0)
        assert not alarm_cfg.state_file.exists()

    def test_garbage_down_since_is_treated_as_new_outage(self, alarm_cfg, mails):
        sul.save_state(alarm_cfg.state_file, {"down_since": "yesterday", "alarm_sent": True})
        sul.check_downtime(alarm_cfg, False, now=1000.0)
        assert mails == []
        assert sul.load_state(alarm_cfg.state_file) == {"down_since": 1000.0, "alarm_sent": False}


class TestUnlockBlockedByLastSeen:
    @pytest.fixture
    def limit_cfg(self, monkeypatch, cfg) -> Config:
        monkeypatch.setenv("SUL_UNLOCK_MAX_DOWN_MINUTES", "15")
        return Config(_env_file=None)

    @pytest.fixture
    def mails(self, monkeypatch):
        sent = []
        monkeypatch.setattr(
            sul, "send_mail", lambda _cfg, subject, body, *, dry_run=False: sent.append((subject, body, dry_run))
        )
        return sent

    def test_disabled_never_blocks(self, cfg, mails):
        sul.save_state(cfg.state_file, {"last_seen_open": 0.0})
        assert sul.unlock_blocked_by_last_seen(cfg, now=10**9) is False
        assert mails == []

    def test_missing_timestamp_fails_open(self, limit_cfg, mails):
        assert sul.unlock_blocked_by_last_seen(limit_cfg, now=1000.0) is False
        assert mails == []

    def test_garbage_timestamp_fails_open(self, limit_cfg, mails):
        sul.save_state(limit_cfg.state_file, {"last_seen_open": "yesterday"})
        assert sul.unlock_blocked_by_last_seen(limit_cfg, now=1000.0) is False

    def test_within_limit_allows(self, limit_cfg, mails):
        sul.save_state(limit_cfg.state_file, {"last_seen_open": 1000.0})
        assert sul.unlock_blocked_by_last_seen(limit_cfg, now=1000.0 + 14 * 60) is False
        assert mails == []

    def test_beyond_limit_blocks_and_alarms(self, limit_cfg, mails):
        sul.save_state(limit_cfg.state_file, {"last_seen_open": 1000.0})
        assert sul.unlock_blocked_by_last_seen(limit_cfg, now=1000.0 + 15 * 60) is True
        assert len(mails) == 1
        assert "Unlock refused" in mails[0][0]
        assert "Provider console" in mails[0][1]
        assert sul.load_state(limit_cfg.state_file)["unlock_blocked_alarm_sent"] is True

    def test_alarm_sent_only_once(self, limit_cfg, mails):
        sul.save_state(limit_cfg.state_file, {"last_seen_open": 1000.0})
        for offset in (20, 25, 30):
            assert sul.unlock_blocked_by_last_seen(limit_cfg, now=1000.0 + offset * 60) is True
        assert len(mails) == 1

    def test_port_recovery_resets_alarm_flag(self, limit_cfg, mails):
        sul.save_state(limit_cfg.state_file, {"last_seen_open": 1000.0, "unlock_blocked_alarm_sent": True})
        sul.check_downtime(limit_cfg, True, now=5000.0)
        assert sul.load_state(limit_cfg.state_file) == {"last_seen_open": 5000.0}

    def test_dry_run_previews_mail_but_writes_no_state(self, limit_cfg, mails):
        sul.save_state(limit_cfg.state_file, {"last_seen_open": 1000.0})
        assert sul.unlock_blocked_by_last_seen(limit_cfg, dry_run=True, now=1000.0 + 20 * 60) is True
        assert mails[0][2] is True
        assert sul.load_state(limit_cfg.state_file) == {"last_seen_open": 1000.0}


class TestResetLastSeen:
    def test_sets_now_and_clears_flags(self, monkeypatch, cfg):
        sul.save_state(cfg.state_file, {"last_seen_open": 1.0, "down_since": 2.0, "unlock_blocked_alarm_sent": True})
        monkeypatch.setattr(sul, "wall_time", lambda: 5000.0)
        assert sul.reset_last_seen(cfg) == sul.EXIT_OK
        assert sul.load_state(cfg.state_file) == {"last_seen_open": 5000.0}

    def test_main_reset_does_not_run_workflow(self, monkeypatch, cfg):
        monkeypatch.setattr(sul, "Config", lambda: Config(_env_file=None))
        monkeypatch.setattr(sul, "_run", lambda *_a, **_k: pytest.fail("workflow must not run"))
        assert sul.main(reset=True) == sul.EXIT_OK
        assert "last_seen_open" in sul.load_state(cfg.state_file)


class TestSetupLogging:
    def test_info_level_hides_debug(self, capsys):
        sul.setup_logging(verbose=False)
        logger.debug("hidden-debug")
        logger.info("shown-info")
        out = capsys.readouterr().out
        assert "shown-info" in out
        assert "hidden-debug" not in out

    def test_debug_level_shows_debug(self, capsys):
        sul.setup_logging(verbose=True)
        logger.debug("shown-debug")
        assert "shown-debug" in capsys.readouterr().out

    def test_replaces_previous_sink(self, capsys):
        sul.setup_logging(verbose=False)
        sul.setup_logging(verbose=False)
        logger.info("once")
        assert capsys.readouterr().out.count("once") == 1


class TestMain:
    @pytest.fixture
    def workflow(self, monkeypatch, cfg):
        """Patch all I/O of `main()` and record calls; defaults describe the happy path."""
        # `Config()` must not read a real `.env` file
        monkeypatch.setattr(sul, "Config", lambda: Config(_env_file=None))
        # The local environment (host_keys, sendmail, ...) is not what these tests are about
        monkeypatch.setattr(sul, "preflight_checks", lambda _cfg, **_k: [])

        state = SimpleNamespace(
            prod_open=False,
            banner=b"SSH-2.0-dropbear_2022.83\r\n",
            allowed=True,
            forced=False,
            control_error=None,
            send_error=None,
            calls=[],
            downtime_calls=[],
        )

        def fake_is_port_open(host, port, timeout=1.0):
            state.calls.append(("is_port_open", host, port))
            return state.prod_open

        def fake_read_banner(host, port, timeout=2.0):
            state.calls.append(("read_banner", host, port))
            return state.banner

        def fake_control(_cfg):
            state.calls.append(("control",))
            if state.control_error:
                raise state.control_error
            if not state.allowed:
                return sul.Decision.DENY
            return sul.Decision.FORCE if state.forced else sul.Decision.ALLOW

        def fake_send(_cfg):
            state.calls.append(("send",))
            if state.send_error:
                raise state.send_error

        def fake_notify(_cfg, *, success, detail, dry_run=False):
            state.calls.append(("notify", success, detail, dry_run))

        monkeypatch.setattr(sul, "is_port_open", fake_is_port_open)
        monkeypatch.setattr(sul, "read_banner", fake_read_banner)
        monkeypatch.setattr(sul, "unlock_allowed_by_control_server", fake_control)
        monkeypatch.setattr(sul, "send_passphrase", fake_send)
        monkeypatch.setattr(sul, "verify_unlock", lambda _cfg: state.calls.append(("verify",)))

        def fake_check_downtime(_cfg, port_open, *, dry_run=False):
            state.downtime_calls.append((port_open, dry_run))

        monkeypatch.setattr(sul, "notify", fake_notify)
        monkeypatch.setattr(sul, "check_downtime", fake_check_downtime)
        return state

    @staticmethod
    def called(state, name: str) -> bool:
        return any(call[0] == name for call in state.calls)

    def test_last_seen_block_skips_csv_and_unlock(self, monkeypatch, workflow, cfg):
        monkeypatch.setattr(sul, "unlock_blocked_by_last_seen", lambda _cfg, *, dry_run=False: True)
        assert sul.main() == sul.EXIT_NOT_ALLOWED
        assert not self.called(workflow, "control")
        assert not self.called(workflow, "send")

    def test_force_flag_overrides_last_seen_block(self, monkeypatch, workflow):
        monkeypatch.setenv("SUL_CONTROL_CSV_URL", "https://example.invalid/c.csv")
        monkeypatch.setattr(sul, "unlock_blocked_by_last_seen", lambda *_a, **_k: pytest.fail("must be skipped"))
        workflow.forced = True
        assert sul.main() == sul.EXIT_OK
        assert self.called(workflow, "send")

    def test_allow_flag_does_not_override_last_seen_block(self, monkeypatch, workflow):
        monkeypatch.setenv("SUL_CONTROL_CSV_URL", "https://example.invalid/c.csv")
        monkeypatch.setattr(sul, "unlock_blocked_by_last_seen", lambda _cfg, *, dry_run=False: True)
        assert sul.main() == sul.EXIT_NOT_ALLOWED
        assert self.called(workflow, "control")
        assert not self.called(workflow, "send")

    def test_invalid_config_returns_error(self, monkeypatch, capsys):
        monkeypatch.setattr(sul, "Config", lambda: Config(_env_file=None))
        assert sul.main() == sul.EXIT_ERROR
        out = capsys.readouterr().out
        assert "SUL_SSH_IP" in out
        assert "SUL_LUKS_PASS" in out

    def test_invalid_config_does_not_log_secret(self, monkeypatch, capsys):
        monkeypatch.setenv("SUL_LUKS_PASS", "s3cret")
        monkeypatch.setattr(sul, "Config", lambda: Config(_env_file=None))
        assert sul.main() == sul.EXIT_ERROR
        assert "s3cret" not in capsys.readouterr().out

    def test_server_already_up(self, workflow):
        workflow.prod_open = True
        assert sul.main() == sul.EXIT_OK
        assert workflow.calls == [("is_port_open", "192.0.2.1", 22)]
        assert not self.called(workflow, "notify")

    def test_check_downtime_receives_prod_port_state(self, workflow):
        sul.main()
        workflow.prod_open = True
        sul.main(dry_run=True)
        assert workflow.downtime_calls == [(False, False), (True, True)]

    def test_dropbear_unreachable(self, workflow):
        workflow.banner = None
        assert sul.main() == sul.EXIT_OK
        assert self.called(workflow, "read_banner")
        assert not self.called(workflow, "send")
        assert not self.called(workflow, "notify")

    def test_not_dropbear(self, workflow):
        workflow.banner = b"SSH-2.0-OpenSSH_9.6\r\n"
        assert sul.main() == sul.EXIT_OK
        assert not self.called(workflow, "send")
        assert not self.called(workflow, "notify")

    def test_dry_run_does_not_send_but_previews_notification(self, workflow):
        assert sul.main(dry_run=True) == sul.EXIT_OK
        assert not self.called(workflow, "send")
        assert workflow.calls[-1][0] == "notify"
        assert workflow.calls[-1][1] is True
        assert workflow.calls[-1][3] is True

    def test_unlocks_without_control_server(self, workflow):
        assert sul.main() == sul.EXIT_OK
        assert ("read_banner", "192.0.2.1", 22) in workflow.calls
        assert not self.called(workflow, "control")
        assert self.called(workflow, "send")
        assert workflow.calls[-1][0] == "notify"
        assert workflow.calls[-1][1] is True

    def test_control_server_allows(self, workflow, monkeypatch):
        monkeypatch.setenv("SUL_CONTROL_CSV_URL", "https://example.invalid/control.csv")
        assert sul.main() == sul.EXIT_OK
        assert self.called(workflow, "control")
        assert self.called(workflow, "send")
        assert workflow.calls[-1][0] == "notify"
        assert workflow.calls[-1][1] is True

    def test_control_server_denies(self, workflow, monkeypatch):
        monkeypatch.setenv("SUL_CONTROL_CSV_URL", "https://example.invalid/control.csv")
        workflow.allowed = False
        assert sul.main() == sul.EXIT_NOT_ALLOWED
        assert not self.called(workflow, "send")
        assert not self.called(workflow, "notify")

    def test_control_server_request_error(self, workflow, monkeypatch):
        monkeypatch.setenv("SUL_CONTROL_CSV_URL", "https://example.invalid/control.csv")
        workflow.control_error = urllib.error.URLError("down")
        assert sul.main() == sul.EXIT_ERROR
        assert not self.called(workflow, "send")
        assert not self.called(workflow, "notify")

    def test_force_skips_control_server(self, workflow, monkeypatch):
        monkeypatch.setenv("SUL_CONTROL_CSV_URL", "https://example.invalid/control.csv")
        workflow.allowed = False
        assert sul.main(force=True) == sul.EXIT_OK
        assert not self.called(workflow, "control")
        assert self.called(workflow, "send")

    def test_force_does_not_override_last_seen_block(self, monkeypatch, workflow):
        monkeypatch.setenv("SUL_CONTROL_CSV_URL", "https://example.invalid/control.csv")
        monkeypatch.setattr(sul, "unlock_blocked_by_last_seen", lambda _cfg, *, dry_run=False: True)
        assert sul.main(force=True) == sul.EXIT_NOT_ALLOWED
        assert not self.called(workflow, "control")
        assert not self.called(workflow, "send")

    @pytest.mark.parametrize(
        "error",
        [TimeoutError("slow"), OSError("refused"), FileNotFoundError("host_keys"), RuntimeError("not accepted")],
    )
    def test_send_failure_returns_error(self, workflow, capsys, error):
        workflow.send_error = error
        assert sul.main() == sul.EXIT_ERROR
        assert "SSH connection failed" in capsys.readouterr().out
        assert workflow.calls[-1][0] == "notify"
        assert workflow.calls[-1][1] is False

    def test_debug_flag_enables_debug_logging(self, workflow, capsys):
        sul.main(verbose=True)
        assert "Remote server banner" in capsys.readouterr().out

    def test_hides_debug_output_by_default(self, workflow, capsys):
        sul.main()
        assert "Remote server banner" not in capsys.readouterr().out


class TestPreflight:
    @pytest.fixture(autouse=True)
    def script_dir(self, monkeypatch, tmp_path):
        """Point the module's `__file__` to a temp dir so `.env` and `host_keys` are looked up there."""
        monkeypatch.setattr(sul, "__file__", str(tmp_path / "ssh_unlock_luks.py"))
        monkeypatch.setattr(sul.shutil, "which", lambda _name: "/usr/sbin/sendmail")
        return tmp_path

    def test_env_file_missing_is_ok(self):
        assert sul.check_env_file() == []

    def test_env_file_0600_is_ok(self, script_dir):
        env = script_dir / ".env"
        env.write_text("")
        env.chmod(0o600)
        assert sul.check_env_file() == []

    @pytest.mark.parametrize("mode", [0o644, 0o640, 0o604, 0o666])
    def test_env_file_readable_by_others_is_rejected(self, script_dir, mode):
        env = script_dir / ".env"
        env.write_text("")
        env.chmod(mode)
        (error,) = sul.check_env_file()
        assert "chmod 600" in error

    def test_ssh_key_permissions(self, script_dir, monkeypatch, cfg):
        (script_dir / "host_keys").write_text("")
        key = script_dir / "id"
        key.write_text("")
        key.chmod(0o644)
        monkeypatch.setenv("SUL_SSH_KEY", str(key))
        assert any("SSH key" in e for e in sul.preflight_checks(Config(_env_file=None)))
        key.chmod(0o600)
        assert sul.preflight_checks(Config(_env_file=None)) == []

    def test_missing_host_keys_without_opt_in(self, cfg):
        assert any("host_keys" in e for e in sul.preflight_checks(cfg))

    def test_missing_host_keys_with_opt_in(self, monkeypatch, cfg):
        monkeypatch.setenv("SUL_ALLOW_UNKNOWN_HOST", "1")
        assert sul.preflight_checks(Config(_env_file=None)) == []

    def test_unwritable_state_dir(self, script_dir, monkeypatch, cfg):
        (script_dir / "host_keys").write_text("")
        monkeypatch.setenv("SUL_DOWN_ALARM_MINUTES", "5")
        monkeypatch.setattr(sul.os, "access", lambda *_a: False)
        assert any("State file" in e for e in sul.preflight_checks(Config(_env_file=None)))

    def test_missing_sendmail_only_warns(self, script_dir, monkeypatch, cfg):
        (script_dir / "host_keys").write_text("")
        monkeypatch.setattr(sul.shutil, "which", lambda _name: None)
        monkeypatch.setattr(sul, "SENDMAIL_FALLBACK", str(script_dir / "nope"))
        assert sul.preflight_checks(cfg) == []

    def test_main_aborts_on_bad_env_permissions(self, script_dir):
        env = script_dir / ".env"
        env.write_text("")
        env.chmod(0o644)
        assert sul.main() == sul.EXIT_ERROR

    def test_main_aborts_on_failed_preflight(self, monkeypatch, cfg):
        monkeypatch.setattr(sul, "Config", lambda: Config(_env_file=None))
        monkeypatch.setattr(sul, "is_port_open", lambda *_a, **_k: pytest.fail("must not reach the network"))
        assert sul.main() == sul.EXIT_ERROR  # host_keys missing, no opt-in
