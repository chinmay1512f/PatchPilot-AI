# Minimal image used by the Docker execution backend.
# Build:  docker build -t patchpilot-sandbox:latest sandbox/
# Runs with --network none --cap-drop ALL --read-only --pids-limit --memory, as uid 1000.
FROM python:3.12-slim
RUN pip install --no-cache-dir pytest==8.3.3 && useradd -u 1000 -m runner
USER 1000
WORKDIR /work
