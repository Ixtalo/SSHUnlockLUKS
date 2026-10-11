# Development image (CPU only).
# Python 3.12 matches requires-python in pyproject.toml; includes the non-root user 'vscode' (uid 1000).
FROM mcr.microsoft.com/devcontainers/python:3.12-trixie

RUN apt-get update \
    # bubblewrap + socat: Claude Code Bash sandbox
    && apt-get install -y --no-install-recommends bubblewrap socat bc \
    && rm -rf /var/lib/apt/lists/*

# Poetry >= 2 (pyproject uses the [project] table). Installed into the system Python,
# before VIRTUAL_ENV is set below, so that 'poetry install' can never uninstall poetry itself.
RUN pip install --no-cache-dir "poetry>=2,<3"

# Fixed virtualenv outside the workspace: the workspace is a bind mount and its ./.venv
# belongs to the host (native development without a container). A pre-created venv also
# avoids Poetry's hashed cache path, so PATH can be set statically here.
RUN python3 -m venv /opt/venv \
    && chown -R 1000:1000 /opt/venv

# Set as ENV (not remoteEnv) so every process sees it: terminals, tasks, lifecycle scripts
# and the Python extension. With VIRTUAL_ENV set and virtualenvs.create disabled, Poetry
# installs into /opt/venv instead of creating one of its own.
ENV VIRTUAL_ENV=/opt/venv \
    PATH=/opt/venv/bin:$PATH \
    POETRY_VIRTUALENVS_CREATE=false

USER vscode
