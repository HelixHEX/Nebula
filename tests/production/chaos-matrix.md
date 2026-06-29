# Nebula Production Chaos Matrix

Run fast checks:

```bash
NEBULA_TEST_PROFILE=fast ./tests/production/validate-production.sh
```

Run full production validation:

```bash
docker compose -f tests/production/docker-compose.yml up -d
NEBULA_TEST_PROFILE=production NEBULA_RUN_LOAD_TESTS=1 ./tests/production/validate-production.sh
```

## Required Scenarios

- Ref CAS: concurrent create, stale expected target, idempotent retry, exactly-one-success.
- Idempotency: same key/same payload replay, same key/different payload conflict, cross-repository key isolation.
- Sync sessions: duplicate upload, missing chunk/blob, checksum mismatch, validate/commit race, abort cleanup, expiry cleanup.
- Blob consistency: missing object with metadata, orphaned object, corrupt staged object, repair report.
- Vector indexing: concurrent manifest creation, durable chunk persistence, restart lookup, tombstone/search behavior.
- Registry restart: after staged blob upload, after metadata commit, before artifact cleanup.
- Astracollab receiver: replay, duplicate delivery, queue retry, failed dispatch, malformed payload, invalid signature, invalid secret header.

## Load Thresholds

- Registry sync smoke: `http_req_failed < 1%`, `p95 < 750ms`.
- Deployment receiver: `http_req_failed < 2%`, `p95 < 500ms`.
- A threshold breach blocks production promotion unless the runbook records an accepted capacity exception.
