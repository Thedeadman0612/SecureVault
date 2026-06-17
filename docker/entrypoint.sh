#!/bin/sh
# Run pending Alembic migrations, then hand off to the container's CMD.
#
# Why this runs here and not as a separate compose/orchestration step:
# the SQLite database lives on a mounted volume that may be on a fresh
# (un-migrated) schema the first time the container starts. Running the
# migration on every boot is idempotent — `alembic upgrade head` is a
# no-op once the schema is current — and keeps a single source of truth
# for "is the schema ready" instead of relying on operator memory.
set -e

alembic upgrade head

exec "$@"
