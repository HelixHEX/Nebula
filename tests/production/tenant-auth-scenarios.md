# Tenant Auth Production Scenarios

Run these scenarios against a staging registry configured with `NEBULA_AUTH_PROVIDER=better-auth-rs`.
They prove that Better Auth owns users, organizations, memberships, and API keys while Nebula
enforces repository-level policy and audit evidence.

## Required Fixtures

- `org_a` with user `alice` as owner or admin.
- `org_b` with user `bob` as owner or admin.
- Repository `repo_a` owned by `org_a`.
- Repository `repo_b` owned by `org_b`.
- A Nebula visibility or Cedar policy that allows `alice` to read `repo_a`.

## Scenarios

- Org isolation: an API key with `metadata.org_id=org_a` can read `repo_a` and receives `403` for `repo_b`.
- Repository binding: an API key with `metadata.repository_id=repo_a` receives `403` when used against `repo_b`.
- Insufficient scope: an API key without `nebula.repository:read_path` receives `403` on repository read routes.
- Stale token: an expired Better Auth session or API key receives `401` and does not create an allow audit.
- Revoked key: a revoked Better Auth API key receives `401` from registry routes after revocation.
- Audit evidence: every allowed or denied protected request records actor, repository, resource kind, action, decision, and reason.

## Evidence To Attach

- The request IDs and status codes for each scenario.
- The matching `authorization_audit` records from the registry durable store or persisted registry state.
- The Better Auth API-key IDs involved in the test, never the raw key values.
