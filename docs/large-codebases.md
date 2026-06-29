# Large Codebase Architecture

Nebula's scaling rule:

```txt
No interactive command may require scanning the full repository unless it is explicitly a full-repo maintenance or indexing operation.
```

Interactive work should scale with:

- dirty paths
- materialized paths
- changed subtrees
- indexed search shards
- requested projection paths

not total repository size.

## Design Influences

- Google Piper/CitC: central source of truth with sparse cloud workspaces.
- Meta Sapling/EdenFS: lazy file materialization and overlay state.
- Microsoft GVFS/Scalar/Git partial clone: lazy object hydration, sparse checkout, background maintenance.
- Epic Lore: content-addressed Merkle storage and chunked large files.
- Zoekt/Sourcegraph: sharded exact code search indexes.
- Bazel-scale CI: affected target calculation and remote cache integration.

## Core Structures

Nebula uses:

- `ContentBlob` for canonical file identity.
- `BlobChunk` and `ChunkedBlob` for large files.
- `TreeNode` for Merkle directory nodes.
- `TreeSnapshot.root_tree_id` for snapshot identity.
- `WorkspaceOverlay` for sparse materialized and dirty paths.
- `ProjectionManifest` for policy-filtered Git/deployment views.
- `VectorIndexManifest` for experimental path/hash indexing today and planned semantic search keyed by snapshot.
- `Operation` for mutation history, concurrency foundations, and auditability.
- `AffectedGraph` / `BuildGraphProvider` for CI affected-target integration.

## Large Repo Operations

`neb status`

- Reads workspace overlay state.
- Uses dirty path tracking.
- Does not scan all files.

`neb diff`

- Compares Merkle subtree hashes first.
- Descends only into divergent directories.

`neb save`

- Captures dirty overlay entries.
- Reuses unchanged tree nodes and blobs.

`neb projection preview`

- Evaluates policies into a projection manifest.
- Reports included, redacted, templated, omitted, and blocked paths.

`neb vector search`

- Uses indexed shards. In the current OSS implementation, this means experimental path/content-hash index records rather than production semantic embeddings.
- Must not read source files directly unless hydrating a permitted result.

## Future Work

- Replace JSON local catalogs with SQLite or redb once concurrency and scale require it.
- Watchman/fsmonitor support for dirty path detection.
- Hybrid search: trigram, symbol, and vector indexes.
- Concrete build graph adapters for Bazel, Nx, Turborepo, and language-native systems.
- Git partial clone/promisor-style serving for Git compatibility.
