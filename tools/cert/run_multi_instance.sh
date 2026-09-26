#!/usr/bin/env bash
# CYVRIX V4.2 — start two REAL API instances for multi-instance certification.
# Each instance is a separate uvicorn process with its own DB pool, metric
# registry, and Redis connection; the ONLY shared state is Postgres + Redis
# (the v42 test infra). Endpoints/ports are test-only.
set -euo pipefail
cd "$(dirname "$0")/../.."  # repo root

export PYTHONIOENCODING=utf-8
export DATABASE_URL="postgresql+asyncpg://cyvrix:cyvrix_dev@localhost:5434/cyvrix"
export REDIS_URL="redis://localhost:6381/0"
export ENVIRONMENT="development"
export SECRET_KEY="test-secret-key-for-integration-only-not-for-production-32chars!"
export CYVRIX_TEST_WEBHOOK_SECRET="${CYVRIX_TEST_WEBHOOK_SECRET:-mi-webhook-secret}"
export GITHUB_WEBHOOK_SECRET="$CYVRIX_TEST_WEBHOOK_SECRET"

cleanup() {
  # Kill by LISTENING PORT → Windows PID. $! is an MSYS pid that
  # taskkill cannot see; the port lookup is authoritative.
  for port in 8601 8602; do
    winpid=$(netstat -ano | grep ":$port" | grep LISTENING | awk '{print $5}' | head -1)
    [ -n "$winpid" ] && taskkill //F //T //PID "$winpid" >/dev/null 2>&1 || true
  done
  wait 2>/dev/null || true
}
trap cleanup EXIT

( cd apps/api && uvicorn app.main:app --host 127.0.0.1 --port 8601 > /tmp/cyvrix_mi_a.log 2>&1 ) &
PID_A=$!
( cd apps/api && uvicorn app.main:app --host 127.0.0.1 --port 8602 > /tmp/cyvrix_mi_b.log 2>&1 ) &
PID_B=$!

echo "instances starting: A=$PID_A (:8601) B=$PID_B (:8602)"
sleep 6

# If the ports are already held by a PREVIOUS run (stale instances with
# current code), reuse them rather than failing — the harness only needs
# two live API processes with the current code.
python tools/cert/multi_instance.py

python tools/cert/multi_instance.py
