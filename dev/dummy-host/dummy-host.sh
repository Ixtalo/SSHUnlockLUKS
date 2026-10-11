#!/usr/bin/env bash
# Helper to try out ssh_unlock_luks.py against a dummy "encrypted server" (see README.md).
# Usage: dummy-host.sh {start|run [script args]|logs|stop|clean}
set -euo pipefail

ENGINE="${CONTAINER_ENGINE:-podman}"
NAME="sul-dummy-host"
IMAGE="sul-dummy-host"
INITRAMFS_PORT=22222
PROD_PORT=22200
DUMMY_PASSPHRASE="${DUMMY_PASSPHRASE:-test-passphrase}"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
WORK="${DUMMY_HOST_WORK:-$HERE/.work}"  # overridable, e.g. by the integration tests
RUN_DIR="$WORK/run"  # private copy of the script, so its .env and host_keys do not touch the real ones

die() {
    echo "error: $*" >&2
    exit 1
}

cmd_start() {
    command -v "$ENGINE" >/dev/null || die "'$ENGINE' not found (set CONTAINER_ENGINE to docker?)"
    mkdir -p "$RUN_DIR" "$WORK/bin" "$WORK/mail"

    # Throw-away client key pair for the test (kept in .work, which is gitignored).
    if [[ ! -f "$WORK/id_ed25519" ]]; then
        ssh-keygen -q -t ed25519 -N '' -C 'sul-dummy-host' -f "$WORK/id_ed25519"
    fi

    # Fake sendmail: the script's notification mails land in .work/mail instead of a real MTA.
    cat >"$WORK/bin/sendmail" <<EOF
#!/bin/sh
cat >"$WORK/mail/\$(date +%Y%m%d-%H%M%S-%N).eml"
EOF
    chmod 0755 "$WORK/bin/sendmail"

    "$ENGINE" rm -f "$NAME" >/dev/null 2>&1 || true
    rm -rf "$WORK/state"  # fresh run, no old "last seen open" timestamps

    # With --network=host a port that is already taken makes Dropbear exit at once, while the readiness
    # check below would happily connect to the foreign listener. So fail early with a clear message.
    local port
    for port in "$INITRAMFS_PORT" "$PROD_PORT"; do
        if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
            die "port $port on 127.0.0.1 is already in use by another process (find it with: ss -ltnp | grep :$port)"
        fi
    done

    "$ENGINE" build -q -t "$IMAGE" -f "$HERE/Containerfile" "$HERE"
    # --network=host: with published ports an unused port can still accept connections on the host
    # (userland proxy), but the script needs the production port to be really closed.
    "$ENGINE" run -d --rm --init --network=host --name "$NAME" \
        -e AUTHORIZED_KEY="$(cat "$WORK/id_ed25519.pub")" \
        -e DUMMY_PASSPHRASE="$DUMMY_PASSPHRASE" \
        -e INITRAMFS_PORT="$INITRAMFS_PORT" \
        -e PROD_PORT="$PROD_PORT" \
        "$IMAGE" >/dev/null

    local i
    for i in $(seq 1 20); do
        if (exec 3<>"/dev/tcp/127.0.0.1/$INITRAMFS_PORT") 2>/dev/null; then
            break
        fi
        if [[ -z "$("$ENGINE" ps -q --filter "name=^${NAME}$")" ]]; then
            die "dummy host exited right after start, see: $0 logs"
        fi
        if [[ $i -eq 20 ]]; then
            die "dummy host did not come up, see: $0 logs"
        fi
        sleep 0.5
    done

    # Pin the host key like in the README; it is new for every container start.
    # Retried, because the first handshake right after startup can fail; errors stay visible.
    : >"$RUN_DIR/host_keys"
    for i in 1 2 3 4 5; do
        ssh-keyscan -p "$INITRAMFS_PORT" 127.0.0.1 >"$RUN_DIR/host_keys" || true
        [[ -s "$RUN_DIR/host_keys" ]] && break
        sleep 1
    done
    [[ -s "$RUN_DIR/host_keys" ]] || die "ssh-keyscan returned no host key, see: $0 logs"

    echo "Dummy host is waiting for the passphrase on 127.0.0.1:$INITRAMFS_PORT (production port $PROD_PORT closed)."
    echo "Now run: $0 run [--dry-run|--verbose]"
}

cmd_run() {
    [[ -n "$("$ENGINE" ps -q --filter "name=^${NAME}$")" ]] || die "dummy host is not running, start it with: $0 start"

    cp "$ROOT/ssh_unlock_luks.py" "$ROOT/pyproject.toml" "$RUN_DIR/"
    # Test configuration, created once; edit it to try CSV control, SUL_UNLOCK_MAX_DOWN_MINUTES etc.
    if [[ ! -f "$RUN_DIR/.env" ]]; then
        cat >"$RUN_DIR/.env" <<EOF
SUL_SSH_IP=127.0.0.1
SUL_SSH_PORT=$INITRAMFS_PORT
SUL_PROD_SSH_PORT=$PROD_PORT
SUL_SSH_USER=root
SUL_SSH_KEY=$WORK/id_ed25519
SUL_LUKS_PASS=test-passphrase
SUL_MAIL_TO=test@example.com
SUL_STATE_FILE=$WORK/state/state.json
EOF
    fi
    chmod 600 "$RUN_DIR/.env"  # the pre-flight check requires private permissions

    cd "$ROOT"
    PATH="$WORK/bin:$PATH" poetry run python "$RUN_DIR/ssh_unlock_luks.py" "$@"
}

case "${1:-}" in
    start) cmd_start ;;
    run)
        shift
        cmd_run "$@"
        ;;
    logs) "$ENGINE" logs "$NAME" ;;
    stop) "$ENGINE" stop "$NAME" >/dev/null 2>&1 || true ;;
    clean)
        "$ENGINE" rm -f "$NAME" >/dev/null 2>&1 || true
        rm -rf "$WORK"
        ;;
    *) die "usage: $0 {start|run [script args]|logs|stop|clean}" ;;
esac
