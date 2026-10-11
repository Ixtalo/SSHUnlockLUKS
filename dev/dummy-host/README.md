# Dummy Host

A throw-away container that behaves like a server waiting for its LUKS passphrase in dropbear-initramfs,
so `ssh_unlock_luks.py` can be tried out without a real VPS.

- Real Dropbear (key login only, forced command instead of `cryptroot-unlock`) on `127.0.0.1:22222`.
- Production port `127.0.0.1:22200` stays closed until the correct passphrase arrives, then the "server boots"
  and the port opens.
- The test configuration, a pinned `host_keys`, the state file and the notification mails (fake `sendmail`)
  live in `.work/` (gitignored). Your real `.env` and `host_keys` are not touched.

## Requirements

podman (or `CONTAINER_ENGINE=docker`), `ssh-keygen`, `ssh-keyscan` and Poetry with the project installed.
Linux only: the container uses `--network=host` on purpose, so the production port is really closed.

## Usage

```bash
./dummy-host.sh start           # build, start, pin host key
./dummy-host.sh run --dry-run   # all checks, no passphrase sent
./dummy-host.sh run             # unlocks; mail ends up in .work/mail/
./dummy-host.sh run             # production port is open now: "Server is UP"
./dummy-host.sh logs            # Dropbear log of the dummy
./dummy-host.sh stop            # stop the container
./dummy-host.sh clean           # stop and delete .work/
```

Any arguments after `run` are passed on to the script (`--verbose`, `--dry-run`, `--reset-last-seen`).

## Scenarios

- **Wrong passphrase**: `DUMMY_PASSPHRASE=other ./dummy-host.sh start`, then `run`.
  Expected: "Passphrase was not accepted", exit code 1, failure mail.
- **Last-seen block, CSV control, downtime alarm**: add `SUL_UNLOCK_MAX_DOWN_MINUTES`, `SUL_CONTROL_CSV_URL` or
  `SUL_DOWN_ALARM_MINUTES` to `.work/run/.env` and `start` again. The state file is `.work/state/state.json`.
- **Unpinned host key**: delete `.work/run/host_keys` and add `SUL_ALLOW_UNKNOWN_HOST=1` to `.work/run/.env`.

The passphrase `test-passphrase` is deliberately not secret. The dummy only listens on loopback.

## Automated Integration Tests

`tests/test_integration.py` drives this helper with pytest (unlock flow, wrong passphrase, last-seen block).
The tests start their own container with an isolated work directory (`DUMMY_HOST_WORK`), use the ports
22222/22200 and are deselected by default. Run them on the host (not in the devcontainer):

```bash
poetry run pytest -m integration --no-cov
```
