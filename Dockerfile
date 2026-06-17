# syntax=docker/dockerfile:1

# ---------------------------------------------------------------------------
# Stage 1 — builder
#
# Installs dependencies into a user site-packages directory. Kept separate
# from the final stage so build tooling (a C compiler, in case a dependency
# has no prebuilt wheel for this platform/Python version) never ships in the
# production image.
# ---------------------------------------------------------------------------
FROM python:3.13-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# build-essential + libffi-dev: fallback compiler toolchain for cffi-based
# dependencies (argon2-cffi, cryptography) on platforms without a prebuilt
# wheel. Discarded entirely — this stage is not copied into the final image.
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential libffi-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY requirements.txt .
RUN pip install --user -r requirements.txt

# ---------------------------------------------------------------------------
# Stage 2 — final runtime image
# ---------------------------------------------------------------------------
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/home/appuser/.local/bin:$PATH

# Non-root application user. No login shell, no home directory beyond what's
# needed to hold the installed Python packages.
RUN groupadd --system appuser \
    && useradd --system --gid appuser --create-home --home-dir /home/appuser appuser

WORKDIR /app

COPY --from=builder /root/.local /home/appuser/.local

COPY app/ ./app
COPY alembic.ini ./
COPY docker/entrypoint.sh ./entrypoint.sh

# Test suite is excluded from the image via .dockerignore at the build-context
# level; this removes it again in case a base layer still carries it through
# a build cache.
RUN rm -rf ./app/tests \
    && find . -name "__pycache__" -type d -prune -exec rm -rf {} + \
    && mkdir -p /app/logs /app/data \
    && chmod +x ./entrypoint.sh \
    && chown -R appuser:appuser /app

USER appuser

EXPOSE 8000

# Uses Python's stdlib urllib rather than curl/wget — keeps the final image
# free of extra installed packages purely for a health probe.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:8000/health').status == 200 else 1)"]

ENTRYPOINT ["./entrypoint.sh"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
