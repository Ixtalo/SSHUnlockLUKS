#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""Automatically unlock LUKS at boot via SSH, e.g., with dropbear-initramfs."""
import os
import sys
import logging
import socket
from time import sleep
from pathlib import Path
import requests
from dotenv import load_dotenv
# https://docs.paramiko.org/en/stable/api/client.html
from paramiko import SSHClient

__version__ = "1.3.0"
__date__ = "2021-12-15"
__updated__ = "2023-05-03"
__author__ = "Ixtalo"
__license__ = "AGPL-3.0+"
__email__ = "ixtalo@gmail.com"
__status__ = "Production"

LOGGING_STREAM = sys.stdout
DEBUG = bool(os.environ.get("DEBUG", "").lower() in ("1", "true", "yes"))

# check for Python3
if sys.version_info < (3, 0):
    sys.stderr.write("Minimum required version is Python 3.x!\n")
    sys.exit(1)

# setup logging
logging.basicConfig(level=logging.INFO if not DEBUG else logging.DEBUG,
                    format="%(asctime)s %(levelname)-8s %(message)s",
                    datefmt="%Y-%m-%d %H:%M:%S")

# load configuration environment variables from .env file
load_dotenv()
assert os.getenv("SUL_SSH_IP"), "Missing configuration!"
assert os.getenv("SUL_SSH_PORT"), "Missing configuration!"
assert os.getenv("SUL_LUKS_PASS"), "Missing configuration!"


host = os.getenv("SUL_SSH_IP")
port = int(os.getenv("SUL_SSH_PORT"))
username = os.getenv("SUL_SSH_USER", "root")


# check if the remote server is actually in dropbear-initramfs mode
logging.debug("Trying to connect to %s:%s ...", host, port)
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.settimeout(1)     # 1 seconds timeout
    s.connect((host, port))
    data = s.recv(16)   # bufsize should be power of 2
logging.debug("remote server data: %s", repr(data))
if not data.startswith(b"SSH-2.0-dropbear"):
    logging.warning("No Dropbear-SSH remote endpoint! Nothing to do.")
    sys.exit(0)


# check external CSV "control server"
csv_control_url = os.getenv("SUL_CONTROL_CSV_URL", "")
if csv_control_url:
    logging.info("Checking '%s' ...", csv_control_url)
    # HTTP GET
    r = requests.get(csv_control_url)
    logging.debug("HTTP GET: %s", str(r))
    if not r.ok:
        logging.error("Problem getting CSV control data: %s (%s)", r.reason, str(r))
        sys.exit(1)
    # check each line for a match
    lines = r.content.decode().splitlines()
    do_unlock = False
    for line in lines:
        # expect CSV
        try:
            csv_host, unlock_flag = line.split(",")[0:2]
        except ValueError as ex:
            logging.error("Ignoring invalid CSV line: '%s'", line)
            continue
        logging.debug("line: %s -> %s", csv_host, unlock_flag)
        if csv_host.strip() == host:
            # match found, check if it should actually be unlocked
            if unlock_flag.lower() in ("yes", "1", "true"):
                do_unlock = True
                break
    # URL is given but no yes-unlocking-flag is found
    if do_unlock:
        logging.info("SUL_CONTROL_CSV_URL says to unlock %s", host)
    else:
        logging.error("SUL_CONTROL_CSV_URL is given but no enabled unlocking host is found! Abort.")
        sys.exit(2)


# SSH client
client = SSHClient()

# load server's public key from file
# this key check is important to prevent e.g. MitM-attacks
host_keys_filepath = Path(__file__).parent.joinpath("host_keys")
logging.info("host_keys_filepath: %s", host_keys_filepath.resolve())
client.load_host_keys(str(host_keys_filepath.resolve()))

logging.info("establishing SSH connection to %s@%s:%s...", username, host, port)
client.connect(hostname=host, port=port, username=username, key_filename=os.getenv("SUL_SSH_KEY"))

logging.info("open TTY shell...")
channel = client.invoke_shell()
channel.settimeout(3)
while not channel.recv_ready():
    logging.debug("waiting for SSH pseudo-terminal to be receive-ready...")
    sleep(0.5)
channel.recv(1000)
while not channel.send_ready():
    logging.debug("waiting for SSH pseudo-terminal to be send-ready...")
    sleep(0.5)

logging.info("sending passphrase string plus ENTER/newline ...")
channel.send(b"%s\n" % os.getenv("SUL_LUKS_PASS").encode())

logging.info("waiting 3 seconds (grace time)...")
sleep(3)

logging.debug("closing SSH connection...")
client.close()

logging.info("done.")
