#!/usr/bin/env python3
"""Automatically unlock LUKS at boot via SSH, e.g., with dropbear-initramfs.

Exit codes:
    0 - nothing to do (server is up, not in Dropbear mode, or unreachable) or unlocked
    1 - configuration, pre-flight check or runtime error
    2 - unlocking this host is not allowed (CSV control server says no, or the production port
        was last seen open longer ago than `SUL_UNLOCK_MAX_DOWN_MINUTES`)
"""

from __future__ import annotations

import argparse
import csv
import email.utils
import http.client
import json
import os
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import tomllib
import urllib.request
from collections.abc import Callable
from email.message import EmailMessage
from enum import Enum
from pathlib import Path
from time import monotonic, sleep
from time import time as wall_time
from typing import Annotated, Any, TypeVar

from loguru import logger

# https://docs.paramiko.org/en/stable/api/client.html
from paramiko import AutoAddPolicy, Channel, RejectPolicy, SSHClient
from pydantic import (
    AnyUrl,
    BeforeValidator,
    Field,
    FilePath,
    SecretStr,
    UrlConstraints,
    ValidationError,
)
from pydantic_settings import BaseSettings, SettingsConfigDict

# --- Constants -------------------------------------------------------------------------------------

# Process exit codes. Cron/systemd can use these to tell "nothing to do" apart from real errors.
EXIT_OK = 0
EXIT_ERROR = 1
EXIT_NOT_ALLOWED = 2

# First bytes of the SSH identification string sent by Dropbear (e.g. "SSH-2.0-dropbear_2020.81").
# Used to make sure the port we connect to really is the initramfs Dropbear and not something else.
DROPBEAR_BANNER_PREFIX = b"SSH-2.0-dropbear"

# Flag in the control CSV that allows unlocking and overrides the last-seen block for this run.
FORCE_FLAG = "yes!"
# Short time to let Dropbear take over the passphrase before our SSH connection is closed.
SETTLE_SECONDS = 2.0
# Interval in seconds between two port checks while verifying the unlock.
VERIFY_INTERVAL = 2.0
# Timeout in seconds for the HTTP request to the control CSV server.
HTTP_TIMEOUT = 5
# Upper bound for the downloaded CSV, so a huge (or hostile) response cannot exhaust memory.
MAX_CSV_BYTES = 1024 * 100
# Fallback location of the sendmail binary if it is not found in $PATH.
SENDMAIL_FALLBACK = "/usr/sbin/sendmail"
# Maximum time in seconds to wait for the local MTA to accept the mail.
SENDMAIL_TIMEOUT = 10

# Everything that can go wrong while fetching the control CSV.
# OSError covers network/DNS/TLS errors and HTTPError; HTTPException covers malformed HTTP responses.
FETCH_ERRORS = (OSError, http.client.HTTPException)

# --- Pydantic types ----------------------------------------------------------------------------------

# Port number, valid across the full TCP/UDP range (1-65535).
Port = Annotated[int, Field(ge=1, le=65535)]
# An URL that must use https. Plain http would leak the control CSV in transit.
HttpsUrl = Annotated[AnyUrl, UrlConstraints(allowed_schemes=["https"])]

# Generic type variable for helpers that keep the type of their input.
T = TypeVar("T")


def _expanduser(value: T) -> T | str:
    """Expand a leading `~` so `FilePath` validation resolves it before checking existence."""
    if isinstance(value, str):
        return str(Path(value).expanduser())
    return value


# A path that is `~`-expanded first, then must exist as a file.
ExpandedFilePath = Annotated[FilePath, BeforeValidator(_expanduser)]

# --- Paths and version -------------------------------------------------------------------------------


def _read_version() -> str:
    """Read the project version from `pyproject.toml` next to this script."""
    pyproject = Path(__file__).resolve().parent / "pyproject.toml"
    try:
        with pyproject.open("rb") as fh:
            data = tomllib.load(fh)
        # PEP 621 `[project]` first, legacy Poetry `[tool.poetry]` as fallback.
        return data.get("project", {}).get("version") or data["tool"]["poetry"]["version"]
    except (OSError, KeyError, tomllib.TOMLDecodeError):
        # Fall back to a placeholder so the script still runs, e.g. if only the file was copied to the host.
        return "0.0.0"


__version__ = _read_version()


def _default_state_file() -> Path:
    """Return the default path of the downtime state file below `$XDG_STATE_HOME` (or `~/.local/state`)."""
    # XDG_STATE_HOME is only used if it is set AND non-empty; otherwise the standard XDG default applies.
    base = os.environ.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
    return Path(base) / "ssh_unlock_luks" / "state.json"


# --- Configuration -----------------------------------------------------------------------------------


class Config(BaseSettings):
    """Runtime configuration read from environment variables and the `.env` file next to this script.

    Each field maps to an environment variable via `validation_alias` (e.g. `host` <- `SUL_SSH_IP`).
    Fields without a default are mandatory; a missing or invalid one aborts the run with exit code 1.
    """

    # pydantic-settings options:
    # - env_file: read `.env` next to this script (values from real env vars take precedence over the file).
    # - env_ignore_empty: an empty `SUL_X=` line is treated as "not set" and falls back to the default.
    # - extra="ignore": unknown variables in the environment or `.env` are silently ignored.
    # - frozen: the loaded configuration is immutable after validation.
    model_config = SettingsConfigDict(
        env_file=Path(__file__).resolve().parent / ".env",
        env_file_encoding="utf-8",
        env_ignore_empty=True,
        extra="ignore",
        frozen=True,
    )

    # --- Mandatory: where and how the Dropbear (initramfs) SSH endpoint is reached ---
    host: str = Field(validation_alias="SUL_SSH_IP")  # IP or hostname of the server being unlocked
    port: Port = Field(validation_alias="SUL_SSH_PORT")  # Dropbear port in the initramfs (e.g. 2222)
    # Port of the normal, fully booted SSH server. If it is open, the host is already up and nothing is done.
    prod_port: Port = Field(validation_alias="SUL_PROD_SSH_PORT")

    # How long (in seconds) to watch the ports after sending the passphrase before the unlock counts as failed.
    # Must cover LUKS key derivation (e.g. argon2), the initramfs teardown and the boot up to the production SSH.
    verify_seconds: int = Field(120, ge=1, validation_alias="SUL_VERIFY_SECONDS")

    # --- Optional: downtime monitoring and safety checks (None = feature disabled) ---
    # Send one alarm mail once the production port has been closed for this many minutes.
    down_alarm_minutes: int | None = Field(None, ge=1, validation_alias="SUL_DOWN_ALARM_MINUTES")
    # Refuse automatic unlocking if the production port was last seen open longer ago than this (in minutes).
    # This is the guard against unexpected reboots or manipulated rescue systems.
    unlock_max_down_minutes: int | None = Field(None, ge=1, validation_alias="SUL_UNLOCK_MAX_DOWN_MINUTES")
    # JSON file with `last_seen_open` / outage state. Defaults to $XDG_STATE_HOME/ssh_unlock_luks/state.json.
    state_file: Path = Field(default_factory=_default_state_file, validation_alias="SUL_STATE_FILE")

    # --- Credentials and SSH options ---
    luks_pass: SecretStr = Field(validation_alias="SUL_LUKS_PASS")  # LUKS passphrase; SecretStr keeps it out of logs
    username: str = Field("root", validation_alias="SUL_SSH_USER")  # SSH user on the Dropbear endpoint
    ssh_key: ExpandedFilePath | None = Field(None, validation_alias="SUL_SSH_KEY")  # optional private key file
    # Optional remote CSV that acts as a remote "kill switch": only hosts listed as allowed may be unlocked.
    control_csv_url: HttpsUrl | None = Field(None, validation_alias="SUL_CONTROL_CSV_URL")
    # Explicit opt-in to skip host key verification when no `host_keys` file exists. Insecure (MITM risk).
    allow_unknown_host: bool = Field(False, validation_alias="SUL_ALLOW_UNKNOWN_HOST")

    # --- Notification mail (sent via the local MTA / sendmail) ---
    mail_to: str = Field(validation_alias="SUL_MAIL_TO")  # recipient address
    mail_from: str | None = Field(
        None, validation_alias="SUL_MAIL_FROM"
    )  # if unset, the MTA picks the system default sender
    mail_subject: str = Field("SSHUnlockLUKS: unlock attempt result", validation_alias="SUL_MAIL_SUBJECT")


# --- Enums -------------------------------------------------------------------------------------------


class UnlockState(Enum):
    """Result of the port rules applied to one observation after the passphrase was sent."""

    UNLOCKED = "unlocked"  # production port reachable: the host is booted
    BOOTING = "booting"  # Dropbear port closed, production port not (yet) reachable: boot in progress
    PENDING = "pending"  # Dropbear port still open and production port closed: passphrase not (yet) accepted


class Decision(Enum):
    """Verdict of the CSV control server for this host."""

    DENY = "deny"
    ALLOW = "allow"
    FORCE = "force"  # allow and override the last-seen block


# --- Network helpers ---------------------------------------------------------------------------------


def wait_for(predicate: Callable[[], bool], timeout: float, interval: float = 0.5) -> bool:
    """Poll `predicate` until it is true or `timeout` seconds have passed."""
    # Monotonic clock: unaffected by wall-clock changes such as NTP jumps during boot.
    deadline = monotonic() + timeout
    while not predicate():
        if monotonic() >= deadline:
            return False
        sleep(interval)
    return True


def is_port_open(host: str, port: int, timeout: float = 1.0) -> bool:
    """Return True if a TCP connection to host:port succeeds."""
    try:
        # Only the TCP handshake matters here; the connection is closed again immediately.
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:  # includes timeouts and refused connections
        return False


def read_banner(host: str, port: int, timeout: float = 2.0) -> bytes | None:
    """Read the SSH identification string; return None if unreachable."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            # An SSH server sends its identification string ("SSH-2.0-...") right after the TCP connect,
            # so the first 64 bytes are enough to recognise Dropbear without doing a full handshake.
            return sock.recv(64)
    except TimeoutError:
        logger.info(
            "Dropbear port {}:{} timed out. Host is offline or still booting, or a firewall drops the packets.",
            host,
            port,
        )
    except ConnectionRefusedError:
        logger.info("Connection refused. Dropbear port is closed.")
    except OSError as ex:
        logger.warning("Socket error: {}", ex)
    return None


# --- Unlock verification -----------------------------------------------------------------------------


def evaluate_unlock(*, dropbear_open: bool, prod_open: bool) -> UnlockState:
    """Apply the rule set to the current state of both ports. First matching rule wins."""
    if prod_open:
        return UnlockState.UNLOCKED
    if not dropbear_open:
        return UnlockState.BOOTING
    return UnlockState.PENDING


def _observe_unlock(cfg: Config) -> UnlockState:
    """Probe both ports once and evaluate the unlock state."""
    state = evaluate_unlock(
        dropbear_open=is_port_open(cfg.host, cfg.port),
        prod_open=is_port_open(cfg.host, cfg.prod_port),
    )
    logger.debug("Unlock verification state: {}", state.value)
    return state


def verify_unlock(cfg: Config) -> None:
    """Watch the Dropbear and production ports for `cfg.verify_seconds` until the production port is reachable.

    Returns as soon as the production port is reachable. Raises RuntimeError if it does not happen in time;
    the message tells whether the passphrase was rejected (Dropbear still open) or the boot is just too slow.
    """
    logger.info(
        "Verifying unlock for up to {} s (Dropbear port {} should close, production port {} should open) ...",
        cfg.verify_seconds,
        cfg.port,
        cfg.prod_port,
    )
    deadline = monotonic() + cfg.verify_seconds
    state = _observe_unlock(cfg)
    while state is not UnlockState.UNLOCKED and monotonic() < deadline:
        sleep(VERIFY_INTERVAL)
        state = _observe_unlock(cfg)

    if state is UnlockState.UNLOCKED:
        logger.info("Production SSH port {} is reachable. Unlock verified.", cfg.prod_port)
        return
    if state is UnlockState.BOOTING:
        msg = (
            f"Dropbear port {cfg.port} closed, but production port {cfg.prod_port} "
            f"not reachable within {cfg.verify_seconds} s (boot too slow or failed)."
        )
    else:
        msg = f"Passphrase was not accepted (Dropbear port {cfg.port} still open after {cfg.verify_seconds} s)."
    raise RuntimeError(msg)


# --- Control server (CSV) ----------------------------------------------------------------------------

# Values in the control CSV's second column (compared lowercase) and the decision they stand for.
CSV_FLAG_DECISIONS: dict[str, Decision] = {"1": Decision.ALLOW, "true": Decision.ALLOW, "yes": Decision.ALLOW}


def _parse_csv_decision(text: str, host: str) -> Decision:
    """Return the decision of the first usable CSV row for `host`; DENY if there is none."""
    for row in csv.reader(text.splitlines()):
        # Ignore blank lines and malformed rows that do not have at least host + flag columns.
        if len(row) < 2:
            continue
        csv_host, flag = row[0].strip(), row[1].strip().lower()
        logger.debug("row: {} -> {}", csv_host, flag)
        # Rows for other hosts are skipped, so one CSV can manage many servers.
        if csv_host != host:
            continue
        # The first row for this host with a usable flag decides. Rows with other flags (e.g. "no")
        # are skipped and the search continues, so a later "yes" row for the same host would still allow.
        if flag == FORCE_FLAG:
            return Decision.FORCE
        if flag in CSV_FLAG_DECISIONS:
            return CSV_FLAG_DECISIONS[flag]
    # Host not listed, or listed only with non-allowing flags: fail closed.
    return Decision.DENY


def unlock_allowed_by_control_server(cfg: Config) -> Decision:
    """Ask the optional CSV control server whether this host may be unlocked.

    Expected CSV format: `<host>,<yes|1|true|yes!>` per line; `yes!` additionally overrides the last-seen block.
    """
    logger.info("Checking '{}' ...", cfg.control_csv_url)
    # Scheme is restricted to https by `HttpsUrl`; urlopen follows redirects and raises HTTPError (an OSError) on 4xx/5xx.
    # The response is read with a size cap (MAX_CSV_BYTES) to protect against oversized responses.
    with urllib.request.urlopen(str(cfg.control_csv_url), timeout=HTTP_TIMEOUT) as response:  # noqa: S310
        body = response.read(MAX_CSV_BYTES)
    # Invalid UTF-8 bytes are replaced instead of raising, so a damaged file does not crash the run.
    text = body.decode("utf-8", errors="replace")
    return _parse_csv_decision(text, cfg.host)


def _query_control_server(cfg: Config, *, force: bool) -> Decision | None:
    """Return the control server's verdict; None if the query failed (already logged).

    Without a URL the verdict defaults to ALLOW. `--force` skips the query entirely.
    """
    if cfg.control_csv_url is None:
        return Decision.ALLOW
    if force:
        logger.warning("--force: skipping CSV control server check for {}.", cfg.host)
        return Decision.ALLOW
    try:
        decision = unlock_allowed_by_control_server(cfg)
    except FETCH_ERRORS as ex:
        logger.error("Error querying CSV control server: {}", ex)
        return None
    if decision is not Decision.DENY:
        logger.info("SUL_CONTROL_CSV_URL says to unlock {}", cfg.host)
    return decision


# --- SSH ---------------------------------------------------------------------------------------------


def create_ssh_client(cfg: Config) -> SSHClient:
    """Create an SSH client that verifies the server's host key (fail closed)."""
    client = SSHClient()
    host_keys_file = Path(__file__).resolve().parent / "host_keys"
    logger.info("host_keys_filepath: {}", host_keys_file)
    if host_keys_file.is_file():
        # Known host keys are loaded; a host key that does not match (or is unknown) aborts the connection.
        client.load_host_keys(str(host_keys_file))
        client.set_missing_host_key_policy(RejectPolicy())
    elif cfg.allow_unknown_host:
        # Explicitly allowed by the user: accept and remember any host key without verification.
        logger.warning("Host keys file not found! Verification skipped (MITM risk).")
        client.set_missing_host_key_policy(AutoAddPolicy())  # noqa: S507 - explicit opt-in via SUL_ALLOW_UNKNOWN_HOST
    else:
        # No host keys and no opt-in: refuse to connect rather than silently trusting the server.
        msg = (
            f"{host_keys_file} not found. Create it, or set SUL_ALLOW_UNKNOWN_HOST=1 "
            "to skip host key verification (insecure)."
        )
        raise FileNotFoundError(msg)
    return client


def _wait_for_prompt(channel: Channel) -> None:
    """Wait until the shell prompt/banner has arrived and is ready to be answered, then discard the banner."""
    if not wait_for(channel.recv_ready, timeout=10):
        raise TimeoutError("SSH shell did not become receive-ready")  # noqa: TRY003
    channel.recv(1000)  # discard prompt/banner so it does not interfere with what follows

    if not wait_for(channel.send_ready, timeout=10):
        raise TimeoutError("SSH shell did not become send-ready")  # noqa: TRY003


def send_passphrase(cfg: Config) -> None:
    """Connect to Dropbear and send the LUKS passphrase."""
    logger.info("Establishing SSH connection to {}@{}:{} ...", cfg.username, cfg.host, cfg.port)
    # The context manager closes the SSH connection on exit, whether the unlock succeeded or not.
    with create_ssh_client(cfg) as client:
        client.connect(
            hostname=cfg.host,
            port=cfg.port,
            username=cfg.username,
            key_filename=str(cfg.ssh_key) if cfg.ssh_key else None,  # None -> use default keys / agent
            timeout=10,  # TCP connect timeout
            banner_timeout=10,  # time allowed for the server's SSH banner
        )

        # Dropbear only offers an interactive shell; the initramfs prompts for the passphrase there.
        logger.info("Opening TTY shell ...")
        channel = client.invoke_shell()
        channel.settimeout(5)
        _wait_for_prompt(channel)

        logger.info("Sending passphrase ...")
        # The newline is required: Dropbear's prompt only accepts the input once it is terminated by Enter.
        channel.send(f"{cfg.luks_pass.get_secret_value()}\n".encode())

        # Success is not decided here: the outcome is verified via the ports in `verify_unlock`.
        # Just give Dropbear a moment to take over the input (it may close the session right away).
        wait_for(lambda: channel.closed or channel.exit_status_ready(), timeout=SETTLE_SECONDS, interval=0.2)


# --- E-mail notifications ----------------------------------------------------------------------------


def _build_message(cfg: Config, subject: str, body: str) -> EmailMessage:
    """Build a plain-text RFC 5322 message; the headers are taken from the configuration."""
    msg = EmailMessage()
    msg["To"] = cfg.mail_to
    if cfg.mail_from:  # without a From header, sendmail adds the system default (like mail(1))
        msg["From"] = cfg.mail_from
    msg["Subject"] = subject
    # Many MTAs/spam filters drop or reject mails without these headers (a bare sendmail does not add them).
    msg["Date"] = email.utils.formatdate(localtime=True)
    msg["Message-ID"] = email.utils.make_msgid(domain=socket.getfqdn())
    msg.set_content(body)
    return msg


def _save_preview(msg: EmailMessage) -> None:
    """Log the mail and keep a copy as .eml file that any mail client can open."""
    logger.info("Dry-run: notification e-mail would be sent:\n{}", msg.as_string())
    with tempfile.NamedTemporaryFile(
        mode="w", dir="/tmp", prefix="ssh_unlock_luks_mail_", suffix=".eml", delete=False
    ) as fh:  # delete=False: the file must survive after this function returns
        fh.write(msg.as_string())
    logger.info("Dry-run: notification e-mail saved to {}", fh.name)


def _sendmail(msg: EmailMessage) -> None:
    """Hand the message to the local MTA. Failures are logged as warnings, never raised."""
    # Prefer the sendmail binary from $PATH, fall back to the usual location.
    sendmail = shutil.which("sendmail") or SENDMAIL_FALLBACK
    try:
        # sendmail flags: -oi ignores a single "." line as end of input; the recipient is passed explicitly
        # (like mail(1) does) instead of -t, which some sendmail wrappers handle poorly.
        result = subprocess.run(  # noqa: S603 - fixed args, no shell; path resolved via shutil.which/fixed fallback
            [sendmail, "-oi", "--", msg["To"]],
            input=msg.as_bytes(),
            capture_output=True,
            check=True,
            timeout=SENDMAIL_TIMEOUT,
        )
        logger.info("Notification email handed to {} (To: {})", sendmail, msg["To"])
        if result.stderr:
            logger.debug("sendmail stderr: {}", result.stderr.decode(errors="replace").strip())
    except subprocess.CalledProcessError as ex:
        stderr = (ex.stderr or b"").decode(errors="replace").strip()
        logger.warning("Failed to send notification email: {} {}", ex, stderr)
    except (OSError, subprocess.TimeoutExpired) as ex:
        logger.warning("Failed to send notification email: {}", ex)


def send_mail(cfg: Config, subject: str, body: str, *, dry_run: bool = False) -> None:
    """Send an e-mail via the local MTA.

    In dry-run mode, the message is only printed and saved under `/tmp` for review,
    but never actually sent. Never raises; sending failures are logged as warnings.
    """
    msg = _build_message(cfg, subject, body)
    if dry_run:
        _save_preview(msg)
    else:
        _sendmail(msg)


def notify(cfg: Config, *, success: bool, detail: str, dry_run: bool = False) -> None:
    """Send an e-mail about the outcome of an unlock attempt via the local MTA."""
    # The status is part of the subject, so success and failure can be told apart in the inbox at a glance.
    status = "SUCCESS" if success else "FAILURE"
    send_mail(
        cfg,
        f"{cfg.mail_subject} - {status} ({cfg.host})",
        f"Unlock attempt for {cfg.host}: {status}\n\n{detail}\n",
        dry_run=dry_run,
    )


def _send_outage_alarm(cfg: Config, minutes: int, *, dry_run: bool) -> None:
    """Mail the alarm for a production port that has been closed for too long."""
    send_mail(
        cfg,
        f"SSHUnlockLUKS: Prod port {cfg.prod_port} closed for {minutes} min ({cfg.host})",
        f"The production SSH port {cfg.prod_port} of {cfg.host} has been closed for {minutes} min "
        f"(threshold: {cfg.down_alarm_minutes} min).\n\n"
        "RULE: after an unexpected reboot do NOT arm/unlock automatically. Check first:\n"
        "  1. Provider console (screen output, reboot/power history)\n"
        "  2. Logs (last boot, auth, kernel)\n"
        "Only after that, set the host's flag in the control CSV to 'yes' to allow unlocking.\n",
        dry_run=dry_run,
    )


def _send_recovery_notice(cfg: Config, minutes: int, *, dry_run: bool) -> None:
    """Mail the notice that the production port is reachable again after an alarmed outage."""
    send_mail(
        cfg,
        f"SSHUnlockLUKS: Prod port {cfg.prod_port} reachable again ({cfg.host})",
        f"The production SSH port {cfg.prod_port} of {cfg.host} is reachable again "
        f"after an outage of about {minutes} min.\n",
        dry_run=dry_run,
    )


def _send_unlock_refused_mail(cfg: Config, minutes: int, *, dry_run: bool) -> None:
    """Mail the notice that unlocking was refused because the production port was down too long."""
    send_mail(
        cfg,
        f"SSHUnlockLUKS: Unlock refused, prod port {cfg.prod_port} last seen {minutes} min ago ({cfg.host})",
        f"The production SSH port {cfg.prod_port} of {cfg.host} was last seen open {minutes} min ago "
        f"(limit: {cfg.unlock_max_down_minutes} min). The host now waits in Dropbear, "
        "but the unlock was NOT performed.\n\n"
        "Possible causes: unexpected reboot or a manipulated rescue system. Check first:\n"
        "  1. Provider console (screen output, reboot/power history)\n"
        "  2. Logs (last boot, auth, kernel)\n"
        "Then unlock manually, or re-allow unlocking with 'ssh_unlock_luks.py --reset-last-seen' "
        f"or by setting the host's CSV flag to '{FORCE_FLAG}'.\n",
        dry_run=dry_run,
    )


# --- Downtime state ----------------------------------------------------------------------------------


def load_state(path: Path) -> dict[str, Any]:
    """Load the persisted downtime state; a missing or corrupt file yields an empty state."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as ex:
        logger.warning("Ignoring unreadable state file {}: {}", path, ex)
        return {}
    return data if isinstance(data, dict) else {}


def save_state(path: Path, state: dict[str, Any]) -> None:
    """Atomically persist the state (or remove the file if empty). Never raises."""
    try:
        # An empty state is represented by "no file at all", which keeps the state directory clean.
        if not state:
            path.unlink(missing_ok=True)
            return
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        # Write to a temporary file first and rename it afterwards: a crash mid-write
        # cannot leave a half-written (and therefore unreadable) state file behind.
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(json.dumps(state), encoding="utf-8")
        tmp.replace(path)  # atomic rename on the same filesystem
    except OSError as ex:
        logger.warning("Failed to write state file {}: {}", path, ex)


def _timestamp(state: dict[str, Any], key: str) -> float | None:
    """Return a stored timestamp, or None if it is missing or not a number."""
    value = state.get(key)
    return value if isinstance(value, (int, float)) else None


def _minutes_since(timestamp: float, now: float) -> int:
    """Whole minutes elapsed since `timestamp`; `//` floors, so 59.9 s still shows 0 min."""
    return int((now - timestamp) // 60)


def _record_port_open(cfg: Config, state: dict[str, Any], now: float, *, dry_run: bool) -> None:
    """Persist `last_seen_open` and announce the recovery if an outage alarm was sent earlier."""
    down_since = _timestamp(state, "down_since")
    if state.get("alarm_sent") and down_since is not None:
        _send_recovery_notice(cfg, _minutes_since(down_since, now), dry_run=dry_run)
    # Only the "last seen open" timestamp is persisted while up; the outage markers are no longer needed.
    if not dry_run:
        save_state(cfg.state_file, {"last_seen_open": now})


def _record_port_closed(cfg: Config, state: dict[str, Any], now: float, *, dry_run: bool) -> None:
    """Track the outage start and send at most one alarm per outage once the threshold is reached."""
    down_since = _timestamp(state, "down_since")
    # Remember when the outage started (only on the first closed check).
    if down_since is None:
        down_since = now
        state = {**state, "down_since": down_since, "alarm_sent": False}
    minutes = _minutes_since(down_since, now)
    logger.info("Production SSH port {} closed for {} min.", cfg.prod_port, minutes)
    if cfg.down_alarm_minutes is not None and minutes >= cfg.down_alarm_minutes and not state.get("alarm_sent"):
        _send_outage_alarm(cfg, minutes, dry_run=dry_run)
        state["alarm_sent"] = True
    if not dry_run:
        save_state(cfg.state_file, state)


def check_downtime(cfg: Config, port_open: bool, *, dry_run: bool = False, now: float | None = None) -> None:
    """Track when the production port was last seen open and alert on long outages.

    Always records `last_seen_open` while the port is up (used by `unlock_blocked_by_last_seen`).
    If `SUL_DOWN_ALARM_MINUTES` is set, sends a single alarm per outage and a recovery notice
    once the port is open again. In dry-run mode mails are only previewed and no state is written.
    """
    # Neither feature is configured: nothing to track.
    if cfg.down_alarm_minutes is None and cfg.unlock_max_down_minutes is None:
        return
    now = wall_time() if now is None else now  # injectable for tests; wall clock because it is persisted
    state = load_state(cfg.state_file)
    if port_open:
        _record_port_open(cfg, state, now, dry_run=dry_run)
    else:
        _record_port_closed(cfg, state, now, dry_run=dry_run)


def unlock_blocked_by_last_seen(cfg: Config, *, dry_run: bool = False, now: float | None = None) -> bool:
    """Return True if the production port was last seen open longer ago than `SUL_UNLOCK_MAX_DOWN_MINUTES`.

    This catches unexpected reboots or rescue-system manipulation: unlocking is refused and a single
    alarm mail is sent per outage. Without a recorded timestamp the check fails open.
    In dry-run mode the mail is only previewed and no state is written.
    """
    # Feature disabled: never block.
    if cfg.unlock_max_down_minutes is None:
        return False
    now = wall_time() if now is None else now
    state = load_state(cfg.state_file)
    last_seen = _timestamp(state, "last_seen_open")
    # No timestamp yet (e.g. first run): fail open on purpose, otherwise the very first unlock would be blocked.
    if last_seen is None:
        logger.warning("No 'last seen open' timestamp for production port {} yet. Not blocking.", cfg.prod_port)
        return False
    minutes = _minutes_since(last_seen, now)
    # Within the allowed window: the host was up recently, so the unlock is considered safe.
    if minutes < cfg.unlock_max_down_minutes:
        return False

    logger.error(
        "Production SSH port {} was last seen open {} min ago (limit: {} min). Refusing to unlock.",
        cfg.prod_port,
        minutes,
        cfg.unlock_max_down_minutes,
    )
    # Send the refusal mail only once per outage; repeated runs would otherwise spam the inbox.
    if not state.get("unlock_blocked_alarm_sent"):
        _send_unlock_refused_mail(cfg, minutes, dry_run=dry_run)
        if not dry_run:
            save_state(cfg.state_file, {**state, "unlock_blocked_alarm_sent": True})
    return True


def reset_last_seen(cfg: Config) -> int:
    """Set `last_seen_open` to now and clear outage/alarm flags, so unlocking is allowed again."""
    # Writing a fresh state dict (instead of merging) drops `down_since`/`alarm_sent` flags on purpose.
    save_state(cfg.state_file, {"last_seen_open": wall_time()})
    logger.info("Reset 'last seen open' of production port {} to now (state file: {}).", cfg.prod_port, cfg.state_file)
    return EXIT_OK


# --- Pre-flight checks -------------------------------------------------------------------------------


def _check_private_file(path: Path, label: str) -> str | None:
    """Return a problem description if `path` is readable by group/others or owned by someone else."""
    try:
        info = path.stat()
    except OSError as ex:
        return f"{label} {path} is not accessible: {ex}"
    if not stat.S_ISREG(info.st_mode):
        return f"{label} {path} is not a regular file."
    if info.st_mode & 0o077:
        return f"{label} {path} has mode {stat.S_IMODE(info.st_mode):04o}, expected 0600. Fix: chmod 600 {path}"
    if info.st_uid != os.geteuid():
        return f"{label} {path} is owned by uid {info.st_uid}, not by the current user (uid {os.geteuid()})."
    return None


def check_env_file() -> list[str]:
    """Check the `.env` file next to this script (it holds the LUKS passphrase). A missing file is fine."""
    env_file = Path(__file__).resolve().parent / ".env"
    if not env_file.exists():
        logger.debug("No {} found, using environment variables only.", env_file)
        return []
    problem = _check_private_file(env_file, ".env file")
    return [problem] if problem else []


def _nearest_existing_dir(path: Path) -> Path:
    """Return the closest existing ancestor of `path` (the directory that would have to be written to)."""
    current = path.parent
    while not current.exists() and current != current.parent:
        current = current.parent
    return current


def preflight_checks(cfg: Config, *, dry_run: bool = False) -> list[str]:
    """Validate the local environment before any network traffic. Return the list of fatal problems.

    Non-fatal findings are logged as warnings. Everything checked here would otherwise only fail
    late, e.g. after the passphrase was already sent or while the host waits in Dropbear.
    """
    errors: list[str] = []

    # The private key must not be accessible by others (OpenSSH/paramiko users expect the same).
    if cfg.ssh_key is not None and (problem := _check_private_file(cfg.ssh_key, "SSH key")):
        errors.append(problem)

    # Without pinned host keys and without explicit opt-in, create_ssh_client() would refuse anyway.
    host_keys_file = Path(__file__).resolve().parent / "host_keys"
    if not host_keys_file.is_file() and not cfg.allow_unknown_host:
        errors.append(
            f"{host_keys_file} not found. Create it with ssh-keyscan, or set SUL_ALLOW_UNKNOWN_HOST=1 (insecure)."
        )

    # The downtime features persist their state; a read-only location would silently disable them.
    if cfg.down_alarm_minutes is not None or cfg.unlock_max_down_minutes is not None:
        state_dir = _nearest_existing_dir(cfg.state_file)
        if not os.access(state_dir, os.W_OK | os.X_OK):
            errors.append(f"State file {cfg.state_file} cannot be written (no write access to {state_dir}).")

    # Mail failures never abort a run, but the user should know that notifications cannot work.
    if not dry_run and shutil.which("sendmail") is None and not Path(SENDMAIL_FALLBACK).exists():
        logger.warning("No sendmail binary found; notification e-mails cannot be sent.")

    return errors


def _report_preflight(errors: list[str]) -> bool:
    """Log all problems; return True if there are none."""
    for error in errors:
        logger.error("Pre-flight check failed: {}", error)
    return not errors


# --- Workflow ----------------------------------------------------------------------------------------


def setup_logging(verbose: bool) -> None:
    """(Re)configure the loguru sink on stdout."""
    # Remove loguru's default handler first, so messages are not printed twice.
    logger.remove()
    logger.add(
        sys.stdout,
        level="DEBUG" if verbose else "INFO",
        format="{time:YYYY-MM-DD HH:mm:ss} {level: <8} {message}",
    )


def load_config() -> Config | None:
    """Load the configuration; log each validation problem and return None if it is invalid."""
    try:
        return Config()
    except ValidationError as ex:
        # Log every problem at once (not just the first) so all misconfigurations can be fixed in one pass.
        # `include_input=False` keeps secret values such as SUL_LUKS_PASS out of the log.
        for err in ex.errors(include_input=False, include_url=False):
            logger.error("Invalid configuration {}: {}", ".".join(str(part) for part in err["loc"]), err["msg"])
        return None


def _is_dropbear_waiting(cfg: Config) -> bool:
    """Return True if a Dropbear (initramfs) endpoint is listening on the configured port."""
    logger.debug("Trying to connect to {}:{} ...", cfg.host, cfg.port)
    banner = read_banner(cfg.host, cfg.port)
    # No answer at all: host is probably still booting or unreachable. Not an error, so retry on next run.
    if banner is None:
        return False
    logger.debug("Remote server banner: {!r}", banner)
    # Only send the passphrase to a real Dropbear; any other service on that port is ignored.
    if not banner.startswith(DROPBEAR_BANNER_PREFIX):
        logger.warning("No Dropbear SSH endpoint! Nothing to do.")
        return False
    return True


def _perform_unlock(cfg: Config) -> int:
    """Send the passphrase and verify the outcome. Any failure is reported by mail and mapped to EXIT_ERROR."""
    try:
        send_passphrase(cfg)
        verify_unlock(cfg)
    except Exception as ex:  # noqa: BLE001 - any SSH/socket/timeout failure maps to the same exit code
        logger.error("SSH connection failed: {}", ex)
        notify(cfg, success=False, detail=str(ex))
        return EXIT_ERROR

    notify(cfg, success=True, detail="LUKS passphrase accepted; production SSH port is reachable.")
    logger.info("Done.")
    return EXIT_OK


def _run(cfg: Config, *, dry_run: bool, force: bool = False) -> int:
    """Run the unlock workflow with an already validated configuration."""
    # Design decision: the early exits stay inline on purpose. Splitting them into sub-functions would
    # require returning tuples such as (decision, exit_code), which is harder to read than a few returns.
    # Exit silently if the server already booted, to avoid tripping firewall rules on the Dropbear port.
    logger.debug("Checking if production SSH port {} is already open ...", cfg.prod_port)
    prod_open = is_port_open(cfg.host, cfg.prod_port)
    # Always update the downtime bookkeeping, even when there is nothing to unlock.
    check_downtime(cfg, prod_open, dry_run=dry_run)
    if prod_open:
        logger.info("Production SSH port {} is reachable. Server is UP. Nothing to do.", cfg.prod_port)
        return EXIT_OK
    if not _is_dropbear_waiting(cfg):
        return EXIT_OK

    decision = _query_control_server(cfg, force=force)
    if decision is None:
        return EXIT_ERROR
    if decision is Decision.DENY:
        logger.error("SUL_CONTROL_CSV_URL is set but no enabled entry for {} found. Abort.", cfg.host)
        return EXIT_NOT_ALLOWED

    # An explicit FORCE from the CSV skips the last-seen safety check; otherwise that check may block the unlock.
    if decision is Decision.FORCE:
        logger.warning("CSV flag '{}' overrides the last-seen check.", FORCE_FLAG)
    elif unlock_blocked_by_last_seen(cfg, dry_run=dry_run):
        return EXIT_NOT_ALLOWED

    # Dry-run: run every check above, but only send a preview mail instead of the passphrase.
    if dry_run:
        logger.info("Dry-run: skipping passphrase submission.")
        notify(
            cfg,
            success=True,
            detail="Dry-run: this is a preview of the notification e-mail; no unlock was attempted.",
            dry_run=True,
        )
        return EXIT_OK

    return _perform_unlock(cfg)


def main(*, verbose: bool = False, dry_run: bool = False, reset: bool = False, force: bool = False) -> int:
    """Run the unlock workflow and return the process exit code."""
    setup_logging(verbose)
    # Checked before loading: the config contains the LUKS passphrase and must not be group/world readable.
    if not _report_preflight(check_env_file()):
        return EXIT_ERROR
    cfg = load_config()
    if cfg is None:
        return EXIT_ERROR

    if reset:
        return reset_last_seen(cfg)
    if not _report_preflight(preflight_checks(cfg, dry_run=dry_run)):
        return EXIT_ERROR
    return _run(cfg, dry_run=dry_run, force=force)


def _build_parser() -> argparse.ArgumentParser:
    """Build the command line parser. CLI flags only switch behavior; connection settings come from the environment."""
    parser = argparse.ArgumentParser(
        description="Automatically unlock LUKS at boot via SSH, e.g., with dropbear-initramfs."
    )
    parser.add_argument("--verbose", action="store_true", help="Enable verbose debug logging.")
    parser.add_argument("--dry-run", action="store_true", help="Run all checks but do not send the LUKS passphrase.")
    parser.add_argument(
        "--force",
        action="store_true",
        help="Skip the CSV control server check (SUL_CONTROL_CSV_URL). The last-seen check still applies.",
    )
    parser.add_argument(
        "--reset-last-seen",
        action="store_true",
        help="Set the 'last seen open' timestamp to now (re-allow unlocking after a verified reboot) and exit.",
    )
    parser.add_argument("--version", action="version", version=f"ssh_unlock_luks {__version__}")
    return parser


def cli(argv: list[str] | None = None) -> int:
    """Parse command line arguments and run `main()`."""
    args = _build_parser().parse_args(argv)
    return main(
        verbose=args.verbose,
        dry_run=args.dry_run,
        reset=args.reset_last_seen,
        force=args.force,
    )


if __name__ == "__main__":
    sys.exit(cli())
