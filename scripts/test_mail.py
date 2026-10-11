#!/usr/bin/env python3
"""Diagnostic helper: send a test e-mail using the same mechanism as ssh_unlock_luks.py.

Usage: python test_mail.py [--to ADDR] [--from ADDR] [--print-only]
Defaults for --to/--from are taken from SUL_MAIL_TO / SUL_MAIL_FROM (environment or .env).
"""

import argparse
import os
import shutil
import sys
from pathlib import Path

from dotenv import dotenv_values

# The script lives in scripts/, the module and the .env file in the project root.
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import ssh_unlock_luks as sul  # noqa: E402


def main() -> int:
    """Parse the CLI arguments, build a test message and send it (unless --print-only)."""
    env = {**dotenv_values(ROOT / ".env"), **os.environ}
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--to", default=env.get("SUL_MAIL_TO"), help="recipient (default: SUL_MAIL_TO)")
    parser.add_argument(
        "--from",
        dest="sender",
        default=env.get("SUL_MAIL_FROM"),
        help="sender (default: SUL_MAIL_FROM; if empty, the MTA default is used)",
    )
    parser.add_argument("--print-only", action="store_true", help="only show the message, do not send")
    args = parser.parse_args()
    if not args.to:
        parser.error("no recipient: use --to or set SUL_MAIL_TO")

    sul.setup_logging(verbose=True)
    # model_construct skips validation, so the mandatory SSH fields of Config need not be set here.
    cfg = sul.Config.model_construct(mail_to=args.to, mail_from=args.sender)
    msg = sul._build_message(cfg, "SSHUnlockLUKS: test mail", "This is a test mail from test_mail.py.")
    print(f"sendmail binary: {shutil.which('sendmail') or sul.SENDMAIL_FALLBACK}")
    print(f"From: {msg['From']}  To: {msg['To']}\n")
    print(msg.as_string())
    if not args.print_only:
        sul._sendmail(msg)
    return 0


if __name__ == "__main__":
    sys.exit(main())
