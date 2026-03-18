#!/bin/sh
set -e
echo "[entrypoint] running database migrations..."
python migrate.py
echo "[entrypoint] starting application..."
exec python app.py
