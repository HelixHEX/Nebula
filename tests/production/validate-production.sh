#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PROFILE="${NEBULA_TEST_PROFILE:-fast}"
REGISTRY_URL="${NEBULA_REGISTRY_URL:-}"
OPS_REPORT_ARGS=()

if [[ -n "${NEBULA_OPS_REPORT_WEBHOOK:-}" ]]; then
  OPS_REPORT_ARGS=(--report-webhook "$NEBULA_OPS_REPORT_WEBHOOK")
fi

cd "$ROOT"

if command -v cargo-nextest >/dev/null 2>&1; then
  cargo nextest run --profile "$PROFILE"
else
  cargo test --workspace
fi

if [[ -n "$REGISTRY_URL" ]]; then
  curl --fail --silent --show-error "$REGISTRY_URL/health/live" >/dev/null
  curl --fail --silent --show-error "$REGISTRY_URL/health/ready" >/dev/null
  curl --fail --silent --show-error "$REGISTRY_URL/metrics" >/dev/null
fi

if [[ -n "${DATABASE_URL:-}" && -n "${BLOB_STORE_URL:-}" ]]; then
  cargo run -p nebula-cli -- --json ops "${OPS_REPORT_ARGS[@]}" consistency check
fi

if [[ -n "${DATABASE_URL:-}" ]]; then
  cargo run -p nebula-cli -- --json ops "${OPS_REPORT_ARGS[@]}" retention cleanup
fi

if [[ "${NEBULA_RUN_TENANT_AUTH_SCENARIOS:-0}" == "1" ]]; then
  echo "Run and attach evidence for tests/production/tenant-auth-scenarios.md against ${REGISTRY_URL:-the staging registry}."
fi

if [[ "${NEBULA_RUN_RESTORE_DRILL:-0}" == "1" ]]; then
  RESTORE_TARGET="${NEBULA_RESTORE_DRILL_TARGET:-staging}"
  RESTORE_TOOL="${NEBULA_RESTORE_DRILL_TOOL:-managed}"
  RESTORE_BACKUP_ID_ARGS=()
  if [[ -n "${NEBULA_RESTORE_BACKUP_ID:-}" ]]; then
    RESTORE_BACKUP_ID_ARGS=(--backup-id "$NEBULA_RESTORE_BACKUP_ID")
  fi
  cargo run -p nebula-cli -- --json ops "${OPS_REPORT_ARGS[@]}" restore drill \
    --target "$RESTORE_TARGET" \
    --tool "$RESTORE_TOOL" \
    "${RESTORE_BACKUP_ID_ARGS[@]}"
fi

if [[ "${NEBULA_RUN_LOAD_TESTS:-0}" == "1" ]]; then
  if ! command -v k6 >/dev/null 2>&1; then
    echo "k6 is required when NEBULA_RUN_LOAD_TESTS=1" >&2
    exit 1
  fi
  k6 run tests/load/registry-sync.k6.js
  k6 run tests/load/astracollab-deployment-receiver.k6.js
fi
