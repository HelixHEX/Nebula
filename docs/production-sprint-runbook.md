# Nebula Production Sprint Runbook

## Astracollab Deployment Receiver

Receiver URL:

```text
/api/webhook/deployments
```

Consumer URL:

```text
/api/webhook/deployments/consume
```

Required environment:

- `NEBULA_DEPLOY_WEBHOOK_SIGNING_SECRET`: shared signing secret used by Nebula registry and Astracollab receiver.
- `DEPLOYMENT_WEBHOOK_MAX_EVENT_AGE_MS`: replay window, defaults to 5 minutes.
- `QSTASH_TOKEN`, `QSTASH_CURRENT_SIGNING_KEY`: required for production async delivery verification.
- `NEXT_PUBLIC_APP_URL`: public Astracollab URL used when enqueueing QStash jobs.

Manual webhook secret setup:

1. Call `POST /api/v1/integrations/deployments/endpoints` as an org admin.
2. Copy the returned `receiverUrl`, `secretHeaderName`, and one-time `secret`.
3. Configure the external sender to send that header on every deployment webhook.
4. Astracollab stores only `sha256(secret)` and verifies the header with constant-time comparison.

Managed provider setup:

- Vercel, Nebula Cloud, and Horizon Cloud setup should call the same endpoint API and configure the returned header/secret automatically when concrete providers are implemented.
- Provider execution is intentionally not implemented in this sprint. The receiver creates `DeploymentIntent` and `DeploymentIntegrationDispatch` records with `pending_provider_integration`.

Retry semantics:

- Same `request_id + repository_id + projection_id + environment_id` with the same payload returns idempotent success.
- Same key with a different payload returns conflict/quarantine behavior.
- Invalid Nebula signatures, stale timestamps, and invalid configured secret headers are rejected before queueing.

## Nebula Telemetry And Ops Reports

Self-hosted outputs:

- `/metrics`: Prometheus-compatible registry metrics.
- Structured JSON logs: enabled through the registry tracing subscriber.
- `NEBULA_TELEMETRY_EVENT_FILE`: optional JSONL event archive for registry domain events.
- `neb ops ... --report-file <path>`: writes a local JSON report for self-hosted operators.

Hosted Astracollab receiver:

```text
/api/webhook/nebula/ops-reports
```

Shared environment:

- `NEBULA_TELEMETRY_SINKS`: comma-separated sinks, defaults to `json,prometheus`.
- `NEBULA_TELEMETRY_WEBHOOK_URL`: optional event sink URL, usually Astracollab Cloud.
- `NEBULA_TELEMETRY_WEBHOOK_SECRET`: shared signing secret for telemetry events and ops reports.
- `NEBULA_OPS_REPORT_WEBHOOK`: validation-script target for `neb ops` reports.

Astracollab Cloud integration:

- Astracollab Cloud is configured only in hosted deployments, not in self-hosted Nebula.
- Astracollab Cloud maps Nebula scheduled ops to Horizon CronJobs for hosted deployments:
  - `neb ops consistency check --report-webhook $ASTRACOLLAB_NEBULA_OPS_WEBHOOK_URL`
  - `neb ops retention cleanup --report-webhook $ASTRACOLLAB_NEBULA_OPS_WEBHOOK_URL`

## Streaming Sync

Required registry configuration:

- `BLOB_STORE_URL` must point to durable blob storage for streaming sync.
- JSON chunk routes remain only for small/dev compatibility and are bounded by `MAX_IN_MEMORY_BLOB_BYTES`.

Streaming behavior:

- Push exports metadata-only bundles, uploads blob bytes through binary sync routes, validates staged upload records, then commits metadata.
- Pull receives metadata-only large blob records and hydrates them through binary download before local import.
- Commit rejects corrupt staged objects, missing staged records, and object-store divergence before metadata commit.
- Production large-blob paths must not use whole-blob collectors such as `fs::read`, `response.bytes().await`, or object-store `result.bytes().await`.
- Client upload uses `tokio_util::io::ReaderStream` with `reqwest::Body::wrap_stream`.
- Client download uses `bytes_stream()` into a temp file, then validates hash and size before local object promotion.
- Object-store uploads use multipart writes for path-based large blob writes.

Failure modes:

- Missing staged object: validation fails with missing chunk/blob.
- Corrupt upload: binary upload rejects checksum mismatch and removes the temporary staged file.
- Metadata committed but object missing: blob consistency report must be run before promotion; repair by re-uploading the content-addressed object.
- Interrupted upload: retry the same binary blob upload, then rerun validation and commit.

## Production Validation

Fast checks:

```bash
cd nebula
NEBULA_TEST_PROFILE=fast ./tests/production/validate-production.sh
```

Full local validation:

```bash
cd nebula
docker compose -f tests/production/docker-compose.yml up -d
NEBULA_TEST_PROFILE=production NEBULA_RUN_LOAD_TESTS=1 ./tests/production/validate-production.sh
```

Health and ops gates:

```bash
cd nebula
NEBULA_REGISTRY_URL=http://localhost:3000 \
DATABASE_URL=postgres://... \
BLOB_STORE_URL=s3://... \
./tests/production/validate-production.sh
```

The script probes `/health/live`, `/health/ready`, and `/metrics` when `NEBULA_REGISTRY_URL` is set. It runs `neb ops consistency check` when `DATABASE_URL` and `BLOB_STORE_URL` are set, and `neb ops retention cleanup` when `DATABASE_URL` is set. Both ops commands are dry-run by default.

Hosted report validation:

```bash
cd nebula
NEBULA_OPS_REPORT_WEBHOOK=https://app.astracollab.com/api/webhook/nebula/ops-reports \
NEBULA_TELEMETRY_WEBHOOK_SECRET=<shared-secret> \
DATABASE_URL=postgres://... \
BLOB_STORE_URL=s3://... \
./tests/production/validate-production.sh
```

This validates the hosted path without coupling self-hosted Nebula to Horizon: Nebula emits the report, Astracollab receives and persists it, and Horizon remains only the optional runtime/CronJob executor.

Restore drill:

```bash
cd nebula
NEBULA_RUN_RESTORE_DRILL=1 \
NEBULA_RESTORE_DRILL_TARGET=staging \
NEBULA_RESTORE_DRILL_TOOL=managed \
NEBULA_RESTORE_BACKUP_ID=<backup-id> \
./tests/production/validate-production.sh
```

Restore drills must restore metadata and objects into an isolated staging target, run consistency and application checks, and emit an evidence report with `started_at`, `restored_at`, `validated_at`, measured RTO/RPO, validation checks, operator, outcome, and follow-up actions.

Load thresholds:

- Registry sync smoke: `http_req_failed < 1%`, `p95 < 750ms`.
- Astracollab deployment receiver: `http_req_failed < 2%`, `p95 < 500ms`.

Drill cadence:

- Run critical metadata restore drills monthly.
- Run DR game days quarterly.
- Treat any failed restore drill as release-blocking until fixed or explicitly accepted by the release owner.

Post-drill review template:

- What worked:
- What failed:
- RTO/RPO result:
- Customer risk:
- Remediation owner:
- Due date:

Promotion gate:

- `cargo fmt --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- optional `cargo nextest run --profile fast` when available
- Full production validation before release promotion, including health probes, consistency dry-run, retention dry-run, and restore drill evidence for production releases.
