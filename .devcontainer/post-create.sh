#!/usr/bin/env bash
# Project-specific setup. Installs into /opt/venv (see Dockerfile: VIRTUAL_ENV).
set -euo pipefail

poetry install
#pre-commit install
