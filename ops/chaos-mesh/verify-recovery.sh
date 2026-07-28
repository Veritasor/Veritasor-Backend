#!/usr/bin/env bash
# Polls the backend's deep health check after a Chaos Mesh network-partition
# experiment ends, and fails if Postgres/Redis connectivity does not recover
# within RECOVERY_TIMEOUT_SECONDS.
#
# Usage:
#   HEALTH_URL=http://veritasor-backend.veritasor-nonprod:3000/api/health \
#     ./verify-recovery.sh
#
# Run this immediately after the experiment's `duration` elapses (or after
# `kubectl delete -f <manifest>` if you removed it manually) as the last step
# of a chaos run — see README.md.
set -euo pipefail

HEALTH_URL="${HEALTH_URL:-http://localhost:3000/api/health}?mode=deep"
RECOVERY_TIMEOUT_SECONDS="${RECOVERY_TIMEOUT_SECONDS:-30}"
POLL_INTERVAL_SECONDS="${POLL_INTERVAL_SECONDS:-2}"

echo "Verifying recovery at ${HEALTH_URL} (timeout ${RECOVERY_TIMEOUT_SECONDS}s)..."

elapsed=0
while [ "${elapsed}" -lt "${RECOVERY_TIMEOUT_SECONDS}" ]; do
  body="$(curl -fsS "${HEALTH_URL}" 2>/dev/null || true)"

  if [ -n "${body}" ]; then
    status="$(echo "${body}" | grep -o '"status":"[a-z]*"' | head -1 | cut -d'"' -f4)"
    db="$(echo "${body}" | grep -o '"db":"[a-z]*"' | head -1 | cut -d'"' -f4)"
    redis="$(echo "${body}" | grep -o '"redis":"[a-z]*"' | head -1 | cut -d'"' -f4)"

    echo "  t+${elapsed}s: status=${status:-unknown} db=${db:-n/a} redis=${redis:-n/a}"

    if [ "${status}" = "ok" ]; then
      echo "Recovered after ${elapsed}s."
      exit 0
    fi
  else
    echo "  t+${elapsed}s: health endpoint unreachable"
  fi

  sleep "${POLL_INTERVAL_SECONDS}"
  elapsed=$((elapsed + POLL_INTERVAL_SECONDS))
done

echo "FAILED: did not recover within ${RECOVERY_TIMEOUT_SECONDS}s" >&2
exit 1
