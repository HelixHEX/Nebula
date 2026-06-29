# Full Source-Control Product Roadmap

Nebula already has the core graph for an agent-native source-control system:
content-addressed blobs, Merkle snapshots, refs, workspaces, changesets,
proposals, policies, projections, vector manifests, local CLI commands, and a
registry API.

To become a complete source-control product, Nebula needs the product layers
around that graph.

## Product Invariant

Nebula OSS owns source-control protocol and portable storage contracts.
Hosted platforms such as Astracollab provide tenancy, auth, managed storage,
index workers, UI, billing, and integrations.

## Phase 1: Durable Hosted Registry

- Postgres metadata adapter for galaxies, refs, snapshots, workspaces,
  changesets, proposals, policies, projections, Git exports, operation logs,
  review records, status checks, sync sessions, and audit records.
- Object-store blob adapter for raw source bytes, chunks, projection bundles,
  and artifacts.
- pgvector/vector-store adapter for vector manifests, chunks, and index state.
- Explicit migrations, transaction boundaries, idempotent operation writes,
  backup/restore, and readiness checks.

## Phase 2: Auth, Tenancy, And Policy Enforcement

- API tokens, integration tokens, and short-lived session tokens.
- Org/team/actor resolution in hosted products.
- Policy checks enforced on every object read/write, not only projection plans.
- Audit queries for all mutating operations.
- Rate limits and request quotas per actor/integration.

For Astracollab-hosted Nebula, use Better Auth as the concrete auth layer:

- Better Auth sessions identify users in the dashboard and API routes.
- Better Auth organization membership maps to Nebula `Actor::User` and
  `Actor::Team`/organization-scoped policy context.
- Better Auth bearer/API-key/JWT-style plugins can mint service credentials for
  agents, integrations, and internal registry calls.
- The Rust OSS registry should still depend on generic verified claims
  (`Actor`, scopes, org/galaxy context), not Better Auth internals, so
  self-hosters can use another OIDC/JWT/API-key provider.

## Phase 3: Network Sync

- Authenticated `neb clone`, `neb fetch`, `neb push`, and `neb pull`.
- Batch tree/blob/chunk hydration.
- Ref update leases and optimistic concurrency.
- Resumable blob uploads/downloads.
- Incremental sync sessions with explicit operation IDs.

## Phase 4: Review And Merge Product

- Proposal comments and inline path comments.
- Status checks from agents, CI, policy, vector indexing, and deployment systems.
- Approvals, requested changes, merge queues, and release gates.
- Conflict records with deterministic and agent-assisted resolution paths.
- Notifications and webhook events.

## Phase 5: Git Compatibility

- Projection-to-Git commit generation.
- Git remote push and GitHub PR export.
- Git import for existing repositories.
- Authorship, signatures, tags, submodules, LFS compatibility, and later
  promisor/partial-clone support.

## Phase 6: Sparse Workspaces And Huge Galaxies

- SQLite/redb local workspace catalog.
- Dirty-path tracking with fsmonitor/Watchman.
- Lazy tree/blob hydration.
- Background maintenance, compaction, GC, and cache eviction.
- No interactive command may scan the full Galaxy unless explicitly marked as
  maintenance/indexing.

## Phase 7: Hybrid Indexing

- Text/trigram search for exact matches.
- Symbol index for imports, exports, functions, classes, types, routes, and
  package boundaries.
- Vector index for semantic retrieval.
- Incremental indexing from changed paths and projection manifests.
- Permission-filtered retrieval by actor/environment/projection.

## Hosted Astracollab Vector Workers

Yes: Astracollab-hosted Nebula can use Astra/Mastra agents as vector indexing
workers.

The boundary should be:

- Nebula OSS defines `VectorIndexJob`, `VectorIndexManifest`,
  `CodeEmbeddingChunk`, index identities, job status, and policy-aware retrieval
  contracts.
- Astracollab runs Mastra workflows/agents that pick up pending
  `VectorIndexJob`s, hydrate allowed snapshot/projection content, chunk code,
  generate embeddings, write pgvector rows, and update the Nebula manifest.
- Self-hosters can replace the worker with another queue/worker implementation.

This keeps Nebula portable while letting Astracollab use its existing agent
runtime for hosted indexing, summarization, symbol extraction, and background
repair.

## First Implementation Slice

The first productization slice is to add protocol objects for:

- auth tokens
- review comments
- proposal status checks
- webhook endpoints/events
- sync sessions and leases
- vector indexing jobs
- Galaxy API aliases

These objects do not finish the product by themselves, but they prevent the
hosted platform from inventing private one-off tables and make future CLI/API
work target stable protocol resources.
