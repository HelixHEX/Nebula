# Nebula

Nebula is a pre-alpha source-control registry for human and AI-agent work. It models source state as content-addressed blobs, tree snapshots, refs, workspaces, changesets, proposals, policies, projections, and vector index manifests.

Nebula is not production-ready yet. The local CLI and core model are usable for development experiments, but registry hosting, vector search, Git compatibility, backup/restore, and deployment integrations are still experimental unless this README says otherwise.

## Status

| Area | Status | Notes |
| --- | --- | --- |
| Local repository init/save/diff | Works now | Covered by CLI and local-loop tests. |
| Local proposals and merge flow | Works now | Intended for experimentation with Nebula-native review objects. |
| File bundle push/pull | Works now | Local bundle transport only. |
| Registry API | Experimental | Requires explicit auth and durable storage for any non-local use. |
| Streaming blob sync | Experimental | Requires configured object storage. |
| Git migration/export planning | Experimental | Some flows are planning or mirror-only. |
| Vector indexing/search | Experimental | Current implementation is metadata/path based, not production semantic search. |
| Backup, restore, deploy handoff | Planned/experimental | Operational reports exist, provider execution is not a general production feature. |
| CLI registry auth and release automation | Experimental | `neb auth`, cargo-dist, GHCR image publishing, checksums, SBOMs, cargo-audit, and cargo-deny are wired but need validated public tags. |

## Workspace

```txt
nebula/
  crates/
    nebula-core/             # shared source-control model and storage traits
    nebula-registry/         # registry API contracts and HTTP routes
    nebula-registry-server/  # runnable registry server
    nebula-cli/              # `neb` terminal command
    nebula-fs/               # snapshot-backed virtual filesystem overlays
    nebula-git/              # Git projection/export planning
    nebula-vector/           # snapshot-keyed index contracts
  docs/
  tests/
```

## Core Concepts

### Galactic Registry Model
Nebula organizes work at three levels:
- **Galaxy** — A logical registry/project (e.g., "my-app")
- **Workspace** — A branch-like working copy with snapshots (status: `capturing` | `merged`)
- **Snapshot** — Immutable content-addressed tree state (commit equivalent)

### Change Flow
1. **Capture** — `neb save` creates a workspace + snapshot + changeset
2. **Propose** — Bundle changesets into a proposal for review
3. **Review** — Approvals, checks, release gates, comments
4. **Merge** — Three-way merge or fast-forward into target workspace
5. **Project** — Deploy via projections (Horizon, Vercel, etc.)

### Workspaces as Branches
Unlike Git branches, workspaces are first-class registry objects:
- Multiple workspaces per galaxy (feature branches)
- Each tracks `baseSnapshotId` (fork point) and `latestSnapshotId` (tip)
- `status: "merged"` marks the main branch
- Merge targets any workspace via `targetWorkspaceId`

### Proposals
Structured PR equivalent:
- Bundles 1+ changesets
- Policy-gated (Cedar policies per path)
- Review states: open → approved → merged/closed
- Checks and release gates as merge prerequisites

### Policies
Cedar-based, path-scoped:
- `allow`/`deny`/`review_required`/`embargo` per actor/action/path
- Environment-scoped (dev/staging/prod)
- Release gates: immediate | delayed_until | embargoed (+ optional required approver)

### Projections & Deployments
Projections map snapshots → deployment targets:
- Define `includedPaths`, environment, provider (Horizon/Vercel)
- Generate deployment intents on proposal merge
- Vector manifests for semantic search/indexing

## Build From Source

There are no published binary installers yet (see `docs/support-matrix.md`) —
`cargo-dist` is configured, but no public release tag has been validated. The
only supported install path today is building from source.

Requirements:
- Rust 1.89 or newer
- Postgres and object storage only for registry production-path validation
- k6 only for load tests

Clone the repo, then install the `neb` binary onto your `PATH` via Cargo:

```bash
git clone <this repository>
cd nebula
cargo install --path crates/nebula-cli
```

This places `neb` in `$CARGO_HOME/bin` (usually `~/.cargo/bin`), matching the
`install-path` that `cargo-dist` will use for future published installers.
Make sure that directory is on your shell's `PATH` (the standard Rust
installer via https://rustup.rs adds it automatically).

Verify it worked:
```bash
neb --help
```

If you're actively developing Nebula itself rather than just using the CLI,
build and run in place instead so you don't need to reinstall on every
change:

```bash
cargo build --workspace
cargo run -p nebula-cli -- init
cargo run -p nebula-cli -- status
cargo run -p nebula-cli -- save --message "Initial Nebula snapshot"
```

## Local CLI Example

```bash
neb init
neb status
neb save --message "Save current workspace"
neb workspace create auth-fix --from main
neb propose --target main --title "Fix auth redirect"
neb proposal status <proposal-id>
neb merge <proposal-id>
```

Use local bundle remotes for today's sync experiments:

```bash
neb remote add origin file:///tmp/acme-app.nebula.json
neb push
neb clone file:///tmp/acme-app.nebula.json
```

Network registry remotes are experimental and require explicit registry configuration and auth:

```bash
neb remote add origin https://registry.example.com/repo_a.neb
neb auth login --remote origin --token <better-auth-session-or-api-key> --org org_a --repository repo_a --scope nebula.repository:sync_objects
neb auth status --remote origin
neb push origin
neb clone https://registry.example.com/repo_a.neb
```

Credentials are stored in the OS keychain when available. The plaintext fallback is only for explicit local development with `NEBULA_AUTH_PLAINTEXT_STORE=1`.

## Registry Safety

Do not expose a registry server publicly unless authentication and durable storage are configured. Better Auth RS owns production users, organizations, sessions, and API-key lifecycle at `/auth`; Nebula owns repository scopes, Cedar policy, and authorization audits. Local unauthenticated mode is for development only.

For production-path validation, start with:

```bash
NEBULA_TEST_PROFILE=fast ./tests/production/validate-production.sh
```

See:
- `docs/production-registry.md`
- `docs/production-sprint-runbook.md`
- `docs/release-checklist.md`

## Development Checks

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check
cargo audit
```

## Contributing And Security

Read `CONTRIBUTING.md` before opening pull requests and `SECURITY.md` before reporting vulnerabilities. Do not submit generated `target/` output, local `.nebula/` state, private repository data, or secrets.

## License

Apache-2.0. See `LICENSE`.