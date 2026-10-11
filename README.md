# SSH Unlock LUKS

Python script that unlocks LUKS at boot by sending the passphrase via SSH to dropbear-initramfs.

## Use Case

A remote VPS uses LUKS full-disk encryption and only boots after the passphrase is entered.
dropbear-initramfs accepts that passphrase over SSH; this script sends it.

## Requirements

- Python 3.11+ and Poetry (`python3 -m pip install -U --user poetry`)
- SSH keyfile

## Setup

### 1. Host

- Install and configure dropbear-initramfs.

### 2. Client

1. Setup: `poetry install --only=main` (once)
2. Security: `ssh-keyscan -p SSH_HOST_PORT SSH_HOST_IP > host_keys`
   (pins the host's SSH public key so the script only sends the passphrase to the genuine dropbear server; hinders man-in-the-middle attacks)
3. Configuration: `cp env.template .env` and set IP, port, keyfile, passphrase and notification e-mail
   (boolean values accept `1/true/yes/on` and `0/false/no/off`)
   then `chmod 600 .env` (it contains the passphrase; the script refuses to run otherwise)
4. Optional: set up the [CSV control](#csv-control) and `SUL_CONTROL_CSV_URL`
5. Check/test: `poetry run python ssh_unlock_luks.py`
6. Cron job:
   `*/5 * * * *    flock -n /run/lock/ssh_unlock_luks.lock sh -c 'cd /opt/SSHUnlockLUKS/ && .venv/bin/python ssh_unlock_luks.py 2>/dev/null'`
   (`flock -n` prevents overlapping runs; the lock file must be writable by the cron user, otherwise use e.g. `/tmp/ssh_unlock_luks.lock`)

## Downtime Alarm

With `SUL_DOWN_ALARM_MINUTES` set, one e-mail is sent when the production SSH port (`SUL_PROD_SSH_PORT`)
has been closed for longer than that, plus a recovery notice. The outage start is stored in
`SUL_STATE_FILE` (default `~/.local/state/ssh_unlock_luks/state.json`, honours `XDG_STATE_HOME`; not in `/tmp`).
Resolution equals the cron interval. Parallel runs are blocked by a `flock` on `<state file>.lock`.
`--dry-run` only previews mails and writes no state.

## Last-Seen Timeout

With `SUL_UNLOCK_MAX_DOWN_MINUTES` (e.g. `15`), the script stores `last_seen_open` in the state file.
If the port was last open longer ago than the limit, the passphrase is **not** sent, even if the CSV says `yes`.
Instead one alarm e-mail is sent and the exit code is 2. This guards against a forgotten `yes` after an
unexpected reboot. Without a stored timestamp (first run), unlocking is not blocked.

After a verified planned reboot, either set the CSV flag to `yes!` or run `python ssh_unlock_luks.py --reset-last-seen`.
Keep the cron interval clearly below the limit.

## Known Gap: Manipulated `/boot`

An attacker with control over the unencrypted `/boot` could get the passphrase sent to a manipulated
system at the next planned reboot. LUKS and Clevis/Tang do not fully protect against this.

The CSV flag is the manual arming switch. Check `/boot` by hand before setting it to `yes`:

```bash
# Baseline, after every kernel/initramfs/GRUB update
ssh root@VPS 'sha256sum /boot/vmlinuz-* /boot/initrd.img-* /boot/grub/grub.cfg' > ~/boot-baseline.txt

# Before a planned reboot
ssh root@VPS 'sha256sum /boot/vmlinuz-* /boot/initrd.img-* /boot/grub/grub.cfg' \
  | diff - ~/boot-baseline.txt && echo "boot files unchanged" || echo "DIFFERENT - do not arm the unlock"
```

This only detects changes made *before* the check, so it reduces the risk but does not eliminate it.

## CSV Control

If `SUL_CONTROL_CSV_URL` is set, the script downloads the CSV and checks for its host. This lets the
owner approve each unlock centrally.

1. Create a CSV with the columns `HOST,UNLOCK_FLAG`.
2. Host it on a web server.
3. Set `SUL_CONTROL_CSV_URL` in `.env`.

| HOST       | UNLOCK_FLAG |
| ---------- | ----------- |
| 1.2.3.4    | yes         |
| 11.22.33.1 | no          |

- `HOST` must match `SUL_SSH_IP`.
- `UNLOCK_FLAG`: `yes`, `1` or `true` unlocks.
- `yes!` also overrides the last-seen block for that run. Use it only after a verified reboot, then set it back to `no`.
- `--force` on the command line skips the CSV check entirely for that run. The last-seen block still applies.

## E-Mail Notification

Each unlock *attempt* (success or failure) sends an e-mail via the local MTA (Postfix, Exim or any
sendmail-compatible binary). "Nothing to do" cases send no mail.

- `SUL_MAIL_TO` is mandatory.
- Optional: `SUL_MAIL_FROM` (if unset, no `From:` header is set and the local MTA uses its system default sender, like `mail`) and `SUL_MAIL_SUBJECT`.
- `--dry-run` sends nothing. It logs the mail and saves it as an `.eml` file under `/tmp`.

A missing `sendmail` or failed delivery only logs a warning and does not change the exit code.

## Alternatives

- **Mandos**: closest in functionality, pull model with TLS/OpenPGP, approval options. Server must be reachable from the internet.
- **Clevis + Tang**: no stored passphrase, but the Tang server must be reachable from the VPS. No manual release switch.
- **dracut-crypt-ssh**, **dracut-sshd**: for dracut-based distributions.
- `remote-unlock` (passphrase from `pass`)
- `unlock-cryptroot` (interactive)
- `dropbear-auto-unlock` (ZFS only, no LUKS)
