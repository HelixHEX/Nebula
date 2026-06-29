# Hosted Product And Operations

Nebula's OSS registry is the source-control protocol and durable storage layer.
Astracollab is the hosted product layer that turns those protocol objects into a
GitHub-style user experience.

## Hosted Surfaces

Astracollab should expose:

- Galaxy browser for refs, snapshots, workspaces, proposals, and projections.
- File viewer backed by policy-filtered registry reads.
- Diff viewer backed by changesets and merge plans.
- Proposal review with comments, checks, approvals, requested changes, and merge gates.
- Policy editor for actors, environments, integrations, and paths.
- Integration management for GitHub, Vercel, Lucity, CI, and vector workers.
- Audit views for auth decisions, policy decisions, registry writes, sync sessions, and exports.
- Search UI combining exact text, symbol, and vector retrieval.

## Required Production Checks

Before promoting a registry to canonical hosted source of truth:

- Run SQLx migrations in staging and production.
- Verify `/health/live`, `/health/ready`, and `/metrics`.
- Run load tests for concurrent sync bundle push/pull and ref update paths.
- Restore Postgres and object storage into staging.
- Run consistency checks for blob metadata versus object-store objects.
- Validate Cedar schema/policies and policy test fixtures.
- Verify JWKS key rotation with Better Auth.

## Backup And Rollback

Back up Postgres and object storage together. Rollbacks should be migration-aware:

1. Stop write traffic.
2. Snapshot Postgres and object storage.
3. Roll back application version.
4. If a migration is backwards compatible, keep data in place.
5. If not backwards compatible, restore the paired Postgres/object-store snapshot.
6. Re-run consistency checks before accepting write traffic.

## Metrics

The registry exposes a simple Prometheus-compatible `/metrics` endpoint. Hosted
platforms should scrape it and enrich metrics with Lucity/Kubernetes metadata.
Detailed per-actor quotas should be tracked at the auth/policy layer and stored
as audit events.
