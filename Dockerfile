# PatchPilot AI backend (API only) for container hosts such as Render.
# The React frontend is deployed separately (e.g. on Vercel) and calls this API.
#
# Security model on a public host (no Docker-in-Docker available):
#  * the API server runs as root inside the container only so it can drop privileges;
#  * untrusted test code runs as the unprivileged "sandbox" user (uid 10001) with rlimits, a scrubbed
#    environment and an in-process network block, so it cannot read the server's environment
#    (ANTHROPIC_API_KEY), the job database or other jobs' files;
#  * the API key is provided by the host as an environment variable and is never baked into the image.
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY backend/requirements.txt backend/requirements.txt
RUN pip install -r backend/requirements.txt \
 && groupadd --system --gid 10001 sandbox \
 && useradd --system --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin sandbox

COPY backend backend
COPY samples samples
COPY data/recordings/demo-buggy-shop.json data/recordings/demo-buggy-shop.json

ENV PATCHPILOT_DATA_DIR=/app/data \
    PATCHPILOT_SANDBOX_UID=10001 \
    PATCHPILOT_EXECUTION_BACKEND=auto \
    PORT=8000

EXPOSE 8000
# Render (and most hosts) set $PORT; default to 8000 for local `docker run`.
CMD ["sh", "-c", "exec python -m uvicorn --app-dir backend app.main:app --host 0.0.0.0 --port ${PORT:-8000} --proxy-headers --forwarded-allow-ips '*'"]
