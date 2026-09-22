# Nebula Release Checklist

Use this checklist before publishing a public tag, binary, container, or hosted deployment claim.

## Required For Every Public Release

- `cargo fmt --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- `cargo audit --ignore RUSTSEC-2023-0071`
- `cargo deny check`
- README support matrix updated
- CLI help and docs checked for experimental or unsupported claims
- `SECURITY.md`, `CONTRIBUTING.md`, `LICENSE`, and `.gitignore` present

## Required Before Production Claims

- `NEBULA_TEST_PROFILE=fast ./tests/production/validate-production.sh`
- Production validation against Postgres metadata storage
- Production validation against durable object storage
- Auth configured with Better Auth RS (`NEBULA_AUTH_PROVIDER=better-auth-rs`, `NEBULA_AUTH_BASE_URL`, `NEBULA_AUTH_SECRET`) or an explicitly accepted JWKS migration mode
- Admin telemetry API configured with `NEBULA_ADMIN_API_ENABLED=true`, a bootstrap platform admin, and Better Auth protected access checks
- Signed telemetry webhook test delivery validated, including Horizon routing if a dedicated registry telemetry endpoint exists
- Tenant auth evidence from `tests/production/tenant-auth-scenarios.md`
- Restore drill evidence recorded for the target environment
- Backup and retention plan reviewed by a release owner

## Release Workflow

Pull requests and manual dry runs must pass:

```bash
dist plan
docker buildx build --file Dockerfile.registry-server --build-arg RUST_VERSION=1.89 .
```

Temporary advisory exceptions:

- `RUSTSEC-2023-0071`: `rsa` is present through an inactive SQLx MySQL lockfile path while Nebula enables only SQLx Postgres. This is ignored in `cargo audit`.
- `RUSTSEC-2026-0173`: `proc-macro-error2` is transitive through Better Auth 0.10 and `validator`; remove the `deny.toml` ignore when Better Auth upgrades. `cargo audit` treats this as an allowed warning, not a failing vulnerability.

Public tags use the `Release` workflow:

```bash
git tag v0.1.0
git push origin v0.1.0
```

The cargo-dist workflow builds binary artifacts, generates checksums, and creates a GitHub Release. The separate `Release SBOM` workflow attaches a Linux binary SPDX SBOM after release publication. The separate `Registry Container` workflow builds the registry image, publishes tag builds to GHCR, and emits Buildx SBOM/provenance attestations.

## Expected Artifacts

- CI release workflow is enabled
- cargo-dist archives and installers for the configured targets.
- `SHA256SUMS` for everything uploaded from `target/distrib`.
- cargo-dist checksums for binary release artifacts.
- `nebula-linux-binaries.spdx.json` attached by the release SBOM workflow.
- Registry image `<registry>/nebula/nebula-registry-server:<tag>` plus Buildx SBOM/provenance attestations.
- Generated cargo-dist install instructions in the GitHub Release body.

## Artifact Verification

```bash
shasum -a 256 --check SHA256SUMS
dist plan
docker run --rm -p 8080:8080 <registry>/nebula/nebula-registry-server:<tag>
curl --fail http://127.0.0.1:8080/health/live
```

Before promoting a container image, smoke test `/health/live`, `/health/ready`, `/metrics`, Better Auth `/auth` routes, `/admin/v1/health/ready`, `/admin/v1/metrics`, `/admin/v1/telemetry/summary`, signed telemetry webhook test delivery, and a protected registry route with a scoped API key.

For a Horizon-hosted registry release candidate, also verify the image can run
as an HTTP service on port `8080` with `NEBULA_REGISTRY_BACKEND=postgres-object-store`,
external S3-compatible `BLOB_STORE_URL` credentials, Better Auth RS enabled, and
`ASTRACOLLAB_DEPLOY_URL` pointing at Horizon's `/webhooks/nebula` deploy handoff.
Do not promote an image as Horizon-ready based on the file backend alone.

## Rollback Notes

- Binary rollback means pointing install docs and hosted bootstrap scripts back to the previous GitHub Release.
- Container rollback means redeploying the previous GHCR tag or digest.
- If migrations ran, confirm whether they are forward-compatible before rollback; do not drop Better Auth or Nebula tables without a restore plan.
- Revoke any API keys created solely for release validation.

## Release Owner Sign-Off

Record this in the release issue or notes:

- Release version:
- Release owner:
- Validation date:
- Test evidence:
- Known limitations:
- Rollback plan:
