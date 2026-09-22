# Production Registry Operations

Nebula Registry can run as a backend service, but the OSS registry is still pre-alpha. Do not expose it publicly unless auth, durable metadata, object storage, and validation gates are configured.

## Runtime Modes

- `NEBULA_REGISTRY_BACKEND=file`: local/dev mode only. Unauthenticated use requires `NEBULA_REGISTRY_DEV_MODE=1` and must bind to `127.0.0.1` or `localhost`.
- `NEBULA_REGISTRY_BACKEND=postgres`: durable metadata in Postgres, with blob bytes handled by the configured registry/blob mode.
- `NEBULA_REGISTRY_BACKEND=postgres-object-store`: durable metadata in Postgres and source bytes/chunks in an `object_store` backend.

## Required Production Env

- `DATABASE_URL`
- `BLOB_STORE_URL`
- `NEBULA_AUTH_REQUIRED=true`
- `NEBULA_AUTH_PROVIDER=better-auth-rs`
- `NEBULA_AUTH_BASE_URL`
- `NEBULA_AUTH_SECRET`
- `NEBULA_ADMIN_API_ENABLED=true`
- `NEBULA_ADMIN_BOOTSTRAP_USER_IDS` or `NEBULA_ADMIN_BOOTSTRAP_EMAILS`
- `NEBULA_RUN_MIGRATIONS=true`

Optional but common:

- `VECTOR_STORE_URL`
- `NEBULA_AUTH_PROVIDER=jwks` with `NEBULA_AUTH_ISSUER`, `NEBULA_AUTH_AUDIENCE`, and `NEBULA_AUTH_JWKS_URL` during migration from an external issuer.
- `NEBULA_AUTH_TOKEN_AUTHORITY=astracollab-hosted` or `nebula-self-hosted`
- `NEBULA_TELEMETRY_SINKS=json,prometheus`
- `NEBULA_TELEMETRY_EVENT_FILE`
- `NEBULA_TELEMETRY_WEBHOOK_URL`
- `NEBULA_TELEMETRY_WEBHOOK_SECRET`
- `NEBULA_ADMIN_WEBHOOK_SECRET`

## Building The Registry Image

`Dockerfile.registry-server` uses `cargo-chef` with BuildKit cache mounts on
`~/.cargo/registry` and `target/` to split "compile dependencies" from
"compile our crates" into separate layers keyed on `Cargo.lock`. A source-only
change (no dependency bump) should rebuild in a couple of minutes instead of
the ~20 minutes a naive single-stage build takes recompiling the entire
dependency tree from scratch every time. The cache mounts persist on the
BuildKit builder instance (e.g. a `docker buildx create --driver
docker-container` builder), not in the exported image, so reuse the same
builder across builds to keep the cache warm:

```bash
docker buildx build --platform linux/amd64 -f Dockerfile.registry-server \
  -t <registry>/nebula/nebula-registry-server:<unique-tag> --push .
```

Use a unique tag per build (not a floating tag like `nebula`) when the
deployment's `imagePullPolicy` is `IfNotPresent` — otherwise the running pod
won't notice a new image exists under the same tag, and `kubectl rollout
restart` alone won't pull it.

## Local Development Startup

```bash
NEBULA_REGISTRY_DEV_MODE=1 \
NEBULA_AUTH_REQUIRED=false \
HOST=127.0.0.1 \
cargo run -p nebula-registry-server
```

This mode is only for local development.

## Secure Registry Startup

```bash
NEBULA_REGISTRY_BACKEND=postgres-object-store \
DATABASE_URL=postgres://... \
BLOB_STORE_URL=s3://bucket/prefix \
NEBULA_AUTH_REQUIRED=true \
NEBULA_AUTH_PROVIDER=better-auth-rs \
NEBULA_AUTH_BASE_URL=https://registry.example.com \
NEBULA_AUTH_SECRET=<at-least-32-byte-secret> \
cargo run -p nebula-registry-server
```

## Hosting On Horizon

Horizon can host the Nebula registry process, ingress, TLS, logs, and rollout,
but production registry state must live outside the registry pod. Use
`NEBULA_REGISTRY_BACKEND=postgres-object-store` with durable Postgres metadata
and an external S3-compatible object store for source blobs,
chunks, projection bundles, and deploy archives.

Do not use the file backend for a Horizon-hosted production registry. Horizon's
generic app services run as Deployments and should be treated as ephemeral
compute. The registry must be able to restart on a new pod and recover from
Postgres plus object storage alone.

### Bootstrap Flow

Deploying the registry from a Nebula galaxy needs a seed registry because the
new registry cannot serve its own source archive before it exists:

1. Build and publish the registry image from `Dockerfile.registry-server`, or
   use a verified `<registry>/nebula/nebula-registry-server:<tag>` image.
2. Use an existing seed registry to host the `nebula-registry-server` galaxy.
   This can be a local/dev registry for the first deploy, or another managed
   registry.
3. In Horizon, import the seed galaxy with the Nebula Galaxy source option.
4. Configure the created service with the production env matrix below.
5. Verify the hosted registry is healthy.
6. Point Horizon conductor `NEBULA_REGISTRY_URL` at the hosted registry URL.
7. Mirror the registry galaxy into the hosted registry for future self-upgrades.

The first deploy is therefore bootstrapped; subsequent deploys can be
self-hosted once the hosted registry contains the registry service galaxy.

Horizon also has a built-in **Nebula Registry** creation path that deploys a
published registry container image directly and applies the runtime variables
below. Use that path when you already have a released
`<registry>/nebula/nebula-registry-server:<tag>` image and do not need
the first registry service itself to come from a Nebula galaxy.

### Horizon Service Runtime Matrix

Set these values on the Horizon service that runs the registry container:

| Variable | Value |
| --- | --- |
| `HOST` | `0.0.0.0` |
| `PORT` | `8080` |
| `NEBULA_REGISTRY_BACKEND` | `postgres-object-store` |
| `DATABASE_URL` | Postgres connection string for Nebula metadata and Better Auth RS tables |
| `BLOB_STORE_URL` | S3-compatible bucket/prefix, for example `s3://bucket-name/nebula-registry` |
| `NEBULA_RUN_MIGRATIONS` | `true` for first deploy and normal upgrades |
| `NEBULA_AUTH_REQUIRED` | `true` |
| `NEBULA_AUTH_PROVIDER` | `better-auth-rs` |
| `NEBULA_AUTH_BASE_URL` | Public hosted registry URL, for example `https://registry.example.com` |
| `NEBULA_AUTH_SECRET` | At least 32 bytes; store as a Horizon secret |
| `NEBULA_ADMIN_API_ENABLED` | `true` |
| `NEBULA_ADMIN_REQUIRE_BETTER_AUTH` | `true` |
| `NEBULA_ADMIN_BOOTSTRAP_EMAILS` or `NEBULA_ADMIN_BOOTSTRAP_USER_IDS` | Initial platform admin allowlist |
| `NEBULA_ADMIN_BOOTSTRAP_ROLE` | `owner` or `operator` |
| `ASTRACOLLAB_DEPLOY_URL` | Horizon deploy handoff endpoint, usually `https://<horizon-host>/webhooks/nebula` |
| `ASTRACOLLAB_DEPLOY_SIGNING_SECRET` | Shared signing secret for deploy archive handoff |

Also provide the S3 backend variables required by the Rust `object_store`
AWS/S3 implementation, typically:

| Variable | Purpose |
| --- | --- |
| `AWS_ACCESS_KEY_ID` | S3 access key |
| `AWS_SECRET_ACCESS_KEY` | S3 secret key |
| `AWS_REGION` | Provider region, if required |
| `AWS_ENDPOINT_URL` | Custom S3 endpoint URL |
| `AWS_ALLOW_HTTP` | Only for local non-TLS S3-compatible endpoints |

Keep the S3 bucket lifecycle, retention, and backups in the provider. Horizon
does not need to host object storage for this deployment.

### Horizon Responsibilities

Horizon owns the registry service deployment and platform integration:

- route the registry service on port `8080`;
- provide TLS and ingress hostnames;
- inject Postgres, S3, auth, admin, and deploy signing secrets;
- collect logs and run rollouts;
- set conductor `NEBULA_REGISTRY_URL` to the hosted registry URL after cutover.

Nebula owns source-control and registry concerns:

- `/auth` session and API-key lifecycle through Better Auth RS;
- `/admin/v1` platform-admin APIs;
- repository scopes, policies, and authorization audits;
- `/v1/deploy-archives/...` signed archive downloads;
- `/health/live`, `/health/ready`, and `/metrics`.

Better Auth RS is mounted at `/auth` and owns session plus API-key lifecycle:
`/auth/get-session`, `/auth/api-key/create`, `/auth/api-key/list`, and
`/auth/api-key/verify`. Nebula registry routes receive verified user/API-key
claims as generic actors, repository/org bindings, and `PolicyAction` scopes.
When `NEBULA_RUN_MIGRATIONS=true`, registry startup creates the Better Auth RS
Postgres tables (`users`, `sessions`, `api_keys`, organization/admin tables,
and related auth records) separately from Nebula protocol tables.

Nebula-owned API-token creation is disabled when Better Auth RS is configured.
API keys should carry permissions such as `nebula.repository:read_blob`,
`nebula.repository:sync_objects`, and `nebula.repository:deploy`; optional
metadata keys `org_id` and `repository_id` bind a key to an organization or
repository.

## Platform Admin API

The admin API is mounted at `/admin/v1` when `NEBULA_ADMIN_API_ENABLED=true`.
It requires `NEBULA_AUTH_PROVIDER=better-auth-rs` by default and never exposes a
client-side role claim. A request must use a Better Auth session or API key in
`Authorization: Bearer <token>`, then match the server-side
`nebula_platform_admins` allowlist.

Bootstrap at least one platform admin during the first deploy:

```bash
NEBULA_ADMIN_API_ENABLED=true \
NEBULA_ADMIN_REQUIRE_BETTER_AUTH=true \
NEBULA_ADMIN_BOOTSTRAP_USER_IDS=user_123 \
NEBULA_ADMIN_BOOTSTRAP_EMAILS=ops@example.com \
NEBULA_ADMIN_BOOTSTRAP_ROLE=owner
```

`NEBULA_ADMIN_BOOTSTRAP_ROLE` accepts `owner` or `operator`. In Postgres mode
the server creates the admin tables at startup. In file/dev mode the allowlist
is in memory and must be treated as non-durable.

Admin endpoints:

- `GET /admin/v1/health/live`
- `GET /admin/v1/health/ready`
- `GET /admin/v1/metrics`
- `GET /admin/v1/telemetry/summary`
- `GET /admin/v1/telemetry/events`
- `POST /admin/v1/telemetry/events`
- `GET /admin/v1/webhooks/telemetry`
- `PUT /admin/v1/webhooks/telemetry/{id}`
- `POST /admin/v1/webhooks/telemetry/{id}/test`
- `GET /admin/v1/platform-admins`
- `PUT /admin/v1/platform-admins/{user_id_or_email}`
- `DELETE /admin/v1/platform-admins/{user_id_or_email}`

Use the admin API for worker/operator dashboards, internal tooling, and
incident checks. Public probes remain `/health/live`, `/health/ready`, and
`/metrics`.

## Registry Telemetry Webhooks

Nebula can emit telemetry events to a configured file, the in-process admin API
store, and signed outbound webhook targets. The admin webhook APIs use
`x-nebula-event-id`, `x-nebula-sent-at`, and `x-nebula-signature:
sha256:<digest>` headers. Configure a default signing secret with
`NEBULA_ADMIN_WEBHOOK_SECRET`; individual webhook records can override it.

For Horizon-hosted registries, do not point generic registry telemetry at the existing
`POST /webhooks/nebula` endpoint. That Horizon endpoint is a deployment archive
handoff and triggers `DeployArchive`. If Horizon should receive registry health
or telemetry events, add a dedicated Horizon conductor endpoint such as
`POST /webhooks/nebula/registry` and use it as a signed telemetry webhook
target.

## Tenancy Contract

Better Auth owns tenant identity:

- users, sessions, passkeys, and accounts.
- organizations, members, invitations, roles, and active organization selection.
- API-key creation, hashing, verification, revocation, expiration, and org-owned keys.

Nebula owns source-control authorization:

- repository ownership via `RepositoryRecord.org_id`.
- API-key metadata bindings via `org_id` and `repository_id`.
- `PolicyAction` scopes such as `nebula.repository:read_path` and `nebula.repository:sync_objects`.
- Cedar and visibility-policy decisions for protected repository routes.
- authorization audits with actor, repository, resource kind, action, decision, and reason.

Do not add a second user/org membership store in Nebula. If a request crosses org or repository boundaries, the registry must fail closed with `403` and write an authorization audit.

## CLI Registry Auth

Network remotes are still experimental, but the CLI now has first-class credential commands:

```bash
neb auth login --registry-url https://registry.example.com --token <better-auth-session-or-api-key> --org org_a --repository repo_a --scope nebula.repository:sync_objects
neb auth status --registry-url https://registry.example.com
neb auth token create ci --registry-url https://registry.example.com --org org_a --repository repo_a --scope nebula.repository:sync_objects
neb auth token list --registry-url https://registry.example.com
neb auth token revoke <api-key-id> --registry-url https://registry.example.com
neb auth logout --registry-url https://registry.example.com
```

`neb push`, `neb pull`, and registry-backed vector commands load `NEBULA_AUTH_TOKEN` first, then stored credentials for the target registry remote. Credentials use the OS keychain when available. The plaintext fallback is only for explicit local development with `NEBULA_AUTH_PLAINTEXT_STORE=1`, and is written outside `.nebula` with restrictive file permissions.

### Deploy Config

Deploy configs tell the registry where to send a deploy-intent webhook for a
given service (the destination Horizon or another deploy provider registers
for its target). Horizon registers its own deploy config automatically the
first time you deploy a Nebula-galaxy-backed service, but it can also be set
directly:

```bash
neb galaxy deploy-config set <galaxy> <service-id> \
  --deploy-url https://example.com/webhooks/nebula \
  --signing-secret <at-least-16-bytes> \
  --provider-key horizon
neb galaxy deploy-config get <galaxy> <service-id>
neb galaxy deploy-config delete <galaxy> <service-id>
```

`<galaxy>` accepts either a `repo_...` id or `owner/name`. This requires a
token with the `nebula.repository:manage_deploy_config` scope — unlike
`manage_auth` (a Cedar-policy-bypass scope self-issued tokens are
deliberately barred from holding), `manage_deploy_config` is a narrow,
self-service-mintable scope:

```bash
neb auth token create ci --registry-url https://registry.example.com --org org_a --repository repo_a --scope nebula.repository:manage_deploy_config
```

Holding the right scope isn't sufficient on its own, though: the registry's
authorization engine fails closed by default (see "Galaxy Policies" below), so
an explicit allow rule must also exist for the token's actor before
`deploy-config set` will succeed for anything but a `manage_auth` credential.

### Galaxy Policies

Every registry action (beyond what `manage_auth` bypasses) is gated by an
actor-authorization policy that fails closed: a token can carry the right
scope and still get `403 policy denied this registry action` if no rule
explicitly allows that actor. Manage these rules with:

```bash
neb galaxy policy grant <galaxy> <actor> --action <action> [--action <action> ...] [--priority N] [--reason TEXT] [--token <token-id>]
neb galaxy policy list <galaxy>
neb galaxy policy revoke <galaxy> <policy-id>
```

`<actor>` is `public`, or `<kind>:<id>` where kind is `user`, `team`, `agent`,
or `integration`. `public` matches any authenticated actor — use a specific
actor in production; it's mainly useful for testing. `<action>` matches the
`--scope` action names used elsewhere (e.g. `manage_deploy_config`,
`sync_objects`). All three subcommands require `nebula.repository:manage_auth`
— granting/listing/revoking access for other actors is an admin operation.

Example: let a CI token actually use a `manage_deploy_config` scope it was
issued:

```bash
neb galaxy policy grant repo_abc123 integration:ci-deploy-bot --action manage_deploy_config
```

Because Better Auth API keys all resolve to the owning account's
`user:<id>` actor (there's no separate `integration:<name>` identity per
key), a `user:<id>` grant applies to every token and session that account
holds — you can't distinguish "this one CI key" from the rest of the
account's credentials by actor alone. Pass `--token <token-id>` (the
`tok_...` id from `neb auth token list` or `neb auth whoami`) to scope a
grant to one specific token in addition to its actor:

```bash
neb galaxy policy grant repo_abc123 user:usr_owner --action manage_deploy_config --token tok_ci_key_abc
```

This is additive, not a replacement for actor-based grants: omit `--token`
for the previous account-wide behavior. `neb galaxy policy list` shows the
bound `token=...` next to any rule that carries one.

## Horizon Boundary

Horizon owns:

- TLS and ingress routing.
- Kubernetes/service deployment.
- platform-level logs collection.
- platform/ingress-level rate limiting when configured.

Nebula should still keep lightweight app-level protections:

- request tracing.
- request timeout.
- request body limits.
- liveness/readiness probes.
- token scope enforcement before handlers.

## Readiness

`/health/live` only checks that the process is alive.

`/health/ready` checks configured dependencies:

- Postgres connectivity when `DATABASE_URL` is configured.
- Object-store access when `BLOB_STORE_URL` is configured.
- Vector store configuration when `VECTOR_STORE_URL` is configured.

For Horizon-hosted registries, keep `/health/live` and `/health/ready`
available through the service hostname and use `/admin/v1/health/ready` for
admin/operator checks once Better Auth RS is configured.

## Horizon Validation Flow

After deploying the registry service on Horizon:

1. Confirm public probes:
   ```bash
   curl --fail https://registry.example.com/health/live
   curl --fail https://registry.example.com/health/ready
   curl --fail https://registry.example.com/metrics
   ```
2. Confirm admin readiness with a Better Auth session or API key:
   ```bash
   curl --fail \
     -H "Authorization: Bearer $NEBULA_ADMIN_TOKEN" \
     https://registry.example.com/admin/v1/health/ready
   ```
3. Create or mirror a test galaxy into the hosted registry.
4. Set Horizon conductor `NEBULA_REGISTRY_URL=https://registry.example.com`.
5. In Horizon, import a second galaxy by bare id or `.neb` URL and verify the
   generated service source points at the hosted registry.
6. Trigger a deploy intent and verify Horizon receives the signed archive
   handoff at `/webhooks/nebula`.

## Backup And Restore

Back up Postgres and object storage together. Postgres owns object metadata and
Nebula protocol records; object storage owns source bytes/chunks and projection
bundles.

### File → durable import

When migrating a legacy `NEBULA_REGISTRY_BACKEND=file` deployment:

```bash
export DATABASE_URL=postgres://...
export BLOB_STORE_URL=s3://bucket/prefix   # or file:///data/blob-store
neb ops registry import-file \
  --source /data/registry.json \
  --source-blob-store /data/blob-store \
  --run-migrations
```

Use `--dry-run` first to count repositories, OCI manifests/tags, and blob uploads.
After import, start the registry **without** `NEBULA_REGISTRY_PERSISTENCE_PATH`
so Postgres + object store are the only source of truth.

Nebula currently emits backup and restore plans/reports for external tools. It does not provide a complete production backup engine.

Recommended backup cadence:

- Postgres PITR or at least hourly logical backups for hosted production.
- Object-store versioning or lifecycle-protected backups.
- Periodic restore drills into a staging registry.

Restore order:

1. Restore Postgres metadata.
2. Restore object storage bucket/prefix.
3. Start the registry with migrations disabled for the first boot.
4. Run consistency checks for missing blob hashes.
5. Re-enable normal readiness and traffic.
