# SSH Unlock LUKS

Python script to automatically unlock LUKS at boot via SSH, e.g., for dropbear-initramfs.

## Use Case / Scenario

A remote VPS is secured by a LUKS full-disk encryption.
The Linux only boots, if the correct LUKS password is entered.
Via dropbear-initramfs it is possible to send this password remotely via secured SSH.
This Python program does that - it sends the LUKS password via SSH.

## Requirements

* Python 3.8+
    * pipenv, install with `python3 -m pip install --user pipenv`
* SSH keyfile

## Setup

### 1. Host/Master

* Install and configure dropbear-initramfs.
* Optionally, for cron job, set up a web-server and host a dummy file `/ssh_unlock_luks.txt`.

### 2. Client/Slave

1. `pipenv sync`
2. `ssh-keyscan SSH_HOST_IP > host_keys` (put remote SSH server public keys into file `host_keys`)
3. `cp env.template .env` and configure IP, port, keyfile location and passphrase
4. `pipenv run ssh-unlock-luks.py`
5. setup cron job:
   `0 */4 * * *    curl --fail --silent --head --user-agent "SSHUnlockLUKS" http://SSH_HOST_IP/ssh_unlock_luks.txt >/dev/null || (cd /opt/SSHUnlockLUKS/ && .venv/bin/python ssh_unlock_luks.py)`
