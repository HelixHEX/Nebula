# Security Policy

Nebula is pre-alpha and should not be exposed as a production registry without explicit authentication, durable storage, and operator review.

## Supported Versions

No stable release is supported yet. Security fixes land on the main development line until the project publishes versioned releases.

## Reporting a Vulnerability

Please report security issues privately to:

```text
security@astracollab.com
```

Include:

- affected crate, command, endpoint, or configuration
- reproduction steps
- expected and actual behavior
- impact assessment
- any logs or proof of concept that do not expose third-party secrets

Do not open public issues for vulnerabilities until maintainers have triaged the report.

## Current Security Posture

- Treat self-hosted registry deployments as experimental.
- Use Better Auth RS-backed authentication for non-local registry deployments. JWKS mode is only a migration path for an explicitly configured external issuer.
- Keep file-backed, unauthenticated registry mode local-only.
- Do not publish raw API tokens, `.env` files, local `.nebula/` state, or registry persistence snapshots.
- Run the production validation script before making any production-readiness claim.
