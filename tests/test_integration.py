"""Integration tests against the Dropbear dummy host container (see dev/dummy-host/README.md).

They need podman/docker, ssh-keygen/ssh-keyscan and Poetry, bind 127.0.0.1:22222/22200 and take a while,
so they are deselected by default. Run them with: pytest -m integration --no-cov
"""

import email
import email.policy
import json
import os
import shutil
import socket
import subprocess
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
HELPER = ROOT / "dev" / "dummy-host" / "dummy-host.sh"
ENGINE = os.environ.get("CONTAINER_ENGINE", "podman")
INITRAMFS_PORT = 22222
PROD_PORT = 22200
BUILD_TIMEOUT = 300
RUN_TIMEOUT = 60

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not all(shutil.which(tool) for tool in (ENGINE, "poetry", "ssh-keygen", "ssh-keyscan")),
        reason=f"needs {ENGINE}, poetry, ssh-keygen and ssh-keyscan",
    ),
]


def is_port_open(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1):
            return True
    except OSError:
        return False


def wait_for_port(port: int, *, timeout: float = 15.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if is_port_open(port):
            return True
        time.sleep(0.5)
    return False


class DummyHost:
    """Thin wrapper around dummy-host.sh with an isolated work directory."""

    def __init__(self, work: Path) -> None:
        self.work = work

    def helper(self, *args: str, timeout: float = RUN_TIMEOUT) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603 - fixed helper script, test-controlled arguments
            [str(HELPER), *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            cwd=ROOT,
        )

    def start(self) -> None:
        result = self.helper("start", timeout=BUILD_TIMEOUT)
        assert result.returncode == 0, result.stdout + result.stderr

    def run(self, *args: str) -> tuple[int, str]:
        result = self.helper("run", *args)
        return result.returncode, result.stdout + result.stderr

    def mails(self) -> list[email.message.EmailMessage]:
        files = sorted((self.work / "mail").glob("*.eml"))
        return [email.message_from_bytes(f.read_bytes(), policy=email.policy.default) for f in files]  # type: ignore[misc]


@pytest.fixture
def make_dummy_host(monkeypatch, tmp_path):
    """Start a fresh dummy host (optionally with another passphrase); stopped again after the test."""
    hosts: list[DummyHost] = []

    def factory(passphrase: str | None = None) -> DummyHost:
        monkeypatch.setenv("DUMMY_HOST_WORK", str(tmp_path / "work"))
        if passphrase is not None:
            monkeypatch.setenv("DUMMY_PASSPHRASE", passphrase)
        host = DummyHost(tmp_path / "work")
        host.start()
        hosts.append(host)
        return host

    yield factory
    for host in hosts:
        host.helper("stop")


class TestUnlockFlow:
    def test_dry_run_sends_nothing(self, make_dummy_host):
        host = make_dummy_host()

        code, output = host.run("--dry-run")

        assert code == 0
        assert "Dry-run: skipping passphrase submission" in output
        assert host.mails() == []
        # still locked: the dummy is waiting, the production port is closed
        assert is_port_open(INITRAMFS_PORT)
        assert not is_port_open(PROD_PORT)

    def test_unlock_then_server_is_up(self, make_dummy_host):
        host = make_dummy_host()

        code, output = host.run()

        assert code == 0, output
        assert "Done." in output
        assert [m["Subject"] for m in host.mails()][-1].endswith("SUCCESS (127.0.0.1)")

        # the dummy "boots": the production port opens and the next run has nothing to do
        assert wait_for_port(PROD_PORT)
        code, output = host.run()
        assert code == 0
        assert "Server is UP" in output

    def test_wrong_passphrase_fails_with_mail(self, make_dummy_host, monkeypatch):
        host = make_dummy_host("something-else")
        # The failure is only detected after the verify window; keep it well below RUN_TIMEOUT.
        monkeypatch.setenv("SUL_VERIFY_SECONDS", "5")

        code, output = host.run()

        assert code == 1
        assert "Passphrase was not accepted" in output
        assert [m["Subject"] for m in host.mails()][-1].endswith("FAILURE (127.0.0.1)")
        assert not is_port_open(PROD_PORT)


class TestSafetyChecks:
    def test_last_seen_block_refuses_unlock(self, make_dummy_host, monkeypatch):
        host = make_dummy_host()
        # Real environment variables take precedence over the generated .env of the run directory.
        monkeypatch.setenv("SUL_UNLOCK_MAX_DOWN_MINUTES", "1")
        state_file = host.work / "state" / "state.json"
        state_file.parent.mkdir(parents=True, exist_ok=True)
        state_file.write_text(json.dumps({"last_seen_open": 1}), encoding="utf-8")

        code, output = host.run()

        assert code == 2
        assert "Refusing to unlock" in output
        assert "Unlock refused" in host.mails()[-1]["Subject"]
        # the passphrase was not sent: the dummy still waits and the production port is closed
        assert is_port_open(INITRAMFS_PORT)
        assert not is_port_open(PROD_PORT)

    def test_reset_last_seen_allows_unlock_again(self, make_dummy_host, monkeypatch):
        host = make_dummy_host()
        monkeypatch.setenv("SUL_UNLOCK_MAX_DOWN_MINUTES", "1")
        state_file = host.work / "state" / "state.json"
        state_file.parent.mkdir(parents=True, exist_ok=True)
        state_file.write_text(json.dumps({"last_seen_open": 1}), encoding="utf-8")
        assert host.run()[0] == 2

        assert host.run("--reset-last-seen")[0] == 0
        code, output = host.run()

        assert code == 0, output
        assert "Done." in output
