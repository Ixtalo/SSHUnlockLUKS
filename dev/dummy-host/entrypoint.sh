#!/bin/sh
# Simulates a server booting with an encrypted root:
#   phase 1 "initramfs": Dropbear on INITRAMFS_PORT waits for the passphrase (production port closed)
#   phase 2 "prod":      after a successful unlock the initramfs Dropbear stops and, after BOOT_DELAY,
#                        a second Dropbear opens PROD_PORT (the "booted" server)
set -eu

: "${AUTHORIZED_KEY:?AUTHORIZED_KEY (client public key) is required}"
DUMMY_PASSPHRASE="${DUMMY_PASSPHRASE:-test-passphrase}"
INITRAMFS_PORT="${INITRAMFS_PORT:-22222}"
PROD_PORT="${PROD_PORT:-22200}"
BOOT_DELAY="${BOOT_DELAY:-2}"
HOST_KEY=/etc/dropbear/dummy_ed25519_host_key

# Key-only login for root. Dropbear is strict about permissions of ~/.ssh.
mkdir -p /root/.ssh /etc/dropbear
chmod 0700 /root/.ssh
printf '%s\n' "$AUTHORIZED_KEY" >/root/.ssh/authorized_keys
chmod 0600 /root/.ssh/authorized_keys

# The passphrase goes into a file: Dropbear does not pass the environment on to the forced command.
umask 077
printf '%s\n' "$DUMMY_PASSPHRASE" >/run/dummy-passphrase
rm -f /run/unlocked
dropbearkey -t ed25519 -f "$HOST_KEY" >/dev/null

# Options as in Debian's dropbear-initramfs (no port forwarding, no password login),
# bound to loopback only so the dummy is never reachable from the network.
echo "[dummy-host] initramfs phase: Dropbear on 127.0.0.1:${INITRAMFS_PORT}, waiting for the passphrase"
dropbear -F -E -s -j -k -r "$HOST_KEY" -p "127.0.0.1:${INITRAMFS_PORT}" -c /usr/local/bin/fake-unlock.sh &
initramfs_pid=$!
trap 'kill "$initramfs_pid" 2>/dev/null || true; exit 0' TERM INT

while [ ! -e /run/unlocked ]; do
    sleep 0.5
done

# Give the client time to see the session closing, then "boot".
sleep 1
kill "$initramfs_pid" 2>/dev/null || true
wait "$initramfs_pid" 2>/dev/null || true
echo "[dummy-host] unlocked, booting for ${BOOT_DELAY}s (both ports closed)"
sleep "$BOOT_DELAY"

echo "[dummy-host] prod phase: Dropbear on 127.0.0.1:${PROD_PORT}"
trap - TERM INT
exec dropbear -F -E -s -r "$HOST_KEY" -p "127.0.0.1:${PROD_PORT}"
