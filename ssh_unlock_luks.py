#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""Automatically unlock LUKS at boot via SSH, e.g., with dropbear-initramfs."""
import os
import sys
import logging
from time import sleep
from pathlib import Path
from dotenv import load_dotenv
# https://docs.paramiko.org/en/stable/api/client.html
from paramiko import SSHClient

__version__ = "1.1.2"
__date__ = "2021-12-15"
__updated__ = "2022-10-16"
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

# SSH client
client = SSHClient()

# load server's public key from file
# this key check is important to prevent e.g. MitM-attacks
host_keys_filepath = Path(__file__).parent.joinpath("host_keys")
logging.info("host_keys_filepath: %s", host_keys_filepath.resolve())
client.load_host_keys(host_keys_filepath)


host = os.getenv("SUL_SSH_IP")
port = int(os.getenv("SUL_SSH_PORT"))
logging.info("establishing SSH connection to %s:%s...", host, port)
client.connect(hostname=host, port=port,
               username=os.getenv("SUL_SSH_USER", "root"),
               key_filename=os.getenv("SUL_SSH_KEY")
               )

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
