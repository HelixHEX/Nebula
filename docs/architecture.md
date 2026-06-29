# Architecture

Nebula separates source-control storage from product collaboration.

Nebula today is a pre-alpha protocol and implementation. The long-term product vision is a hosted, policy-aware, vector-native source-control system; the current OSS codebase supports local workflows, experimental registry hosting, and projection/index contracts.

## Canonical Model

Nebula owns the durable graph:

```txt
Repository
  Ref
  TreeSnapshot
  ContentBlob
  Workspace
  ChangeSet
  Proposal
  MergeIntent
  Environment
  Policy
  Projection
  VectorIndexManifest
```

Git branches and PRs are projections of this graph. Astracollab reviews are product experiences built on top of Nebula proposals.

## Storage Split

```txt
Metadata DB
  repos, refs, snapshots, entries, workspaces, changesets, proposals,
  merge intents, release gates, policies, environments, integrations, operations

Blob Store
  source bytes, binary files, encrypted private blobs, projection bundles, artifacts

Vector DB
  experimental index chunks keyed by TreeSnapshotId
```

The vector database never stores canonical source content. Today the OSS implementation stores path/content-hash index metadata; production semantic embeddings and retrieval are planned work.

## Git Compatibility

Nebula should start with policy-aware Git export:

```txt
Proposal + Environment + Actor + Policy
  -> Projection
  -> Git branch / commit / PR
```

The Git layer can include, redact, template, omit, block, or embargo paths based on policy decisions. It must fail closed: every file path in the snapshot must have an explicit policy decision before a Git projection can be planned.

Projection previews produce a manifest with:

- included paths
- redacted paths
- templated paths
- omitted paths
- blocked paths

Actual Git branch/commit generation should only be built on top of a projection plan that has no blockers. The current OSS implementation can materialize a blocker-free projection to a filesystem directory; branch/commit/PR creation builds on that output.

## Registry Durability

The registry starts with an in-memory store for tests and a file-backed persistence snapshot for self-hosted/local development. Postgres, S3-compatible blob storage, and pgvector adapters should replace the single-file snapshot for production deployments without changing the core protocol resources.

Public registry deployments must fail closed: unauthenticated file-backed mode is only allowed with explicit local dev configuration.

## Merge And Release Gates

Nebula merge flow is modeled separately from Git:

```txt
Proposal
  -> MergeIntent
  -> MergeResult
  -> Ref update
  -> Operation record
```

Release gates can be immediate, delayed, or embargoed and attach to merge/deployment workflows before public projection.

## Deployment Projections

Hosting platforms often need material that GitHub should not see. Nebula handles that with deployment projections:

```txt
GitHub projection
  safe public source

Vercel production projection
  authorized build source
  environment variables
  short-lived deployment grant
```

Integrations are actors, so Vercel, GitHub, CI, and deploy bots use the same policy model as users, teams, and agents.
