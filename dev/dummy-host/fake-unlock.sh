#!/bin/sh
# Stand-in for Debian's `cryptroot-unlock`, used as Dropbear forced command.
# Asks for the passphrase until it matches; on success it leaves a marker and exits,
# which makes Dropbear close the session (that is what ssh_unlock_luks.py treats as "accepted").
PASS_FILE="${PASS_FILE:-/run/dummy-passphrase}"
UNLOCKED_MARKER="${UNLOCKED_MARKER:-/run/unlocked}"

# Do not echo the passphrase back (like cryptsetup); there is no tty when run from a test.
stty -echo 2>/dev/null || true

expected="$(cat "$PASS_FILE")"
while :; do
    printf 'Please unlock disk cryptroot: '
    IFS= read -r pass || exit 1
    if [ "$pass" = "$expected" ]; then
        echo
        echo "cryptsetup: cryptroot set up successfully"
        touch "$UNLOCKED_MARKER"
        exit 0
    fi
    echo
    echo "No key available with this passphrase."
done
