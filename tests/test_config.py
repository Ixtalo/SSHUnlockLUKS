import pytest
from pydantic import ValidationError

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
    "XDG_STATE_HOME",
)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for name in ENV_VARS:
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def minimal_env(monkeypatch):
    monkeypatch.setenv("SUL_SSH_IP", "192.0.2.1")
    monkeypatch.setenv("SUL_SSH_PORT", "22")
    monkeypatch.setenv("SUL_PROD_SSH_PORT", "22")
    monkeypatch.setenv("SUL_LUKS_PASS", "s3cret")
    monkeypatch.setenv("SUL_MAIL_TO", "admin@example.com")


def load() -> Config:
    return Config(_env_file=None)


def test_defaults(minimal_env):
    cfg = load()
    assert (cfg.host, cfg.port, cfg.prod_port) == ("192.0.2.1", 22, 22)
    assert cfg.username == "root"
    assert cfg.ssh_key is None
    assert cfg.control_csv_url is None
    assert cfg.allow_unknown_host is False
    assert cfg.mail_to == "admin@example.com"
    assert cfg.mail_from is None
    assert cfg.mail_subject == "SSHUnlockLUKS: unlock attempt result"


def test_missing_required_names_variables():
    with pytest.raises(ValidationError) as exc:
        load()
    missing = {err["loc"][0] for err in exc.value.errors()}
    assert missing == {"SUL_SSH_IP", "SUL_SSH_PORT", "SUL_PROD_SSH_PORT", "SUL_LUKS_PASS", "SUL_MAIL_TO"}


@pytest.mark.parametrize("value", ["0", "65536", "-1", "abc"])
def test_invalid_port(minimal_env, monkeypatch, value):
    monkeypatch.setenv("SUL_SSH_PORT", value)
    with pytest.raises(ValidationError):
        load()


def test_empty_optionals_are_treated_as_unset(minimal_env, monkeypatch):
    monkeypatch.setenv("SUL_CONTROL_CSV_URL", "")
    monkeypatch.setenv("SUL_ALLOW_UNKNOWN_HOST", "")
    monkeypatch.setenv("SUL_SSH_KEY", "")
    monkeypatch.setenv("SUL_MAIL_FROM", "")
    cfg = load()
    assert cfg.control_csv_url is None
    assert cfg.allow_unknown_host is False
    assert cfg.ssh_key is None
    assert cfg.mail_from is None


def test_empty_mail_to_is_treated_as_missing(minimal_env, monkeypatch):
    monkeypatch.setenv("SUL_MAIL_TO", "")
    with pytest.raises(ValidationError) as exc:
        load()
    missing = {err["loc"][0] for err in exc.value.errors()}
    assert missing == {"SUL_MAIL_TO"}


def test_ssh_key_must_exist(minimal_env, monkeypatch, tmp_path):
    monkeypatch.setenv("SUL_SSH_KEY", str(tmp_path / "missing_key"))
    with pytest.raises(ValidationError):
        load()


def test_ssh_key_accepts_existing_file(minimal_env, monkeypatch, tmp_path):
    key_file = tmp_path / "id_ed25519"
    key_file.write_text("")
    monkeypatch.setenv("SUL_SSH_KEY", str(key_file))
    cfg = load()
    assert cfg.ssh_key == key_file


def test_control_csv_url_must_be_a_url(minimal_env, monkeypatch):
    monkeypatch.setenv("SUL_CONTROL_CSV_URL", "not-a-url")
    with pytest.raises(ValidationError):
        load()


@pytest.mark.parametrize(
    ("value", "expected"), [("1", True), ("true", True), ("yes", True), ("false", False), ("0", False)]
)
def test_bool_parsing(minimal_env, monkeypatch, value, expected):
    monkeypatch.setenv("SUL_ALLOW_UNKNOWN_HOST", value)
    cfg = load()
    assert cfg.allow_unknown_host is expected


def test_passphrase_is_not_leaked(minimal_env):
    cfg = load()
    assert "s3cret" not in repr(cfg)
    assert cfg.luks_pass.get_secret_value() == "s3cret"


def test_mail_to_is_read_from_env(minimal_env, monkeypatch):
    monkeypatch.setenv("SUL_MAIL_TO", "other@example.com")
    cfg = load()
    assert cfg.mail_to == "other@example.com"


def test_mail_subject_can_be_overridden(minimal_env, monkeypatch):
    monkeypatch.setenv("SUL_MAIL_SUBJECT", "Custom subject")
    cfg = load()
    assert cfg.mail_subject == "Custom subject"


def test_down_alarm_is_disabled_by_default(minimal_env):
    assert load().down_alarm_minutes is None


def test_down_alarm_minutes_is_read_from_env(minimal_env, monkeypatch):
    monkeypatch.setenv("SUL_DOWN_ALARM_MINUTES", "15")
    assert load().down_alarm_minutes == 15


@pytest.mark.parametrize("value", ["0", "-5", "abc"])
def test_invalid_down_alarm_minutes(minimal_env, monkeypatch, value):
    monkeypatch.setenv("SUL_DOWN_ALARM_MINUTES", value)
    with pytest.raises(ValidationError):
        load()


def test_state_file_defaults_to_xdg_state_home(minimal_env, monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    assert load().state_file == tmp_path / "ssh_unlock_luks" / "state.json"


def test_state_file_can_be_overridden(minimal_env, monkeypatch, tmp_path):
    monkeypatch.setenv("SUL_STATE_FILE", str(tmp_path / "custom.json"))
    assert load().state_file == tmp_path / "custom.json"
