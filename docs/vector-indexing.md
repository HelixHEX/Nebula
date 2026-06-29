# Vector Indexing

Nebula is vector-native, not vector-only.

The vector database indexes source content, but canonical source content lives in the blob store and metadata graph.

Current OSS status: experimental. The registry path currently records path/content-hash index metadata and can search those records. It does not generate or store production semantic embeddings yet.

## Identity

Astracollab currently indexes code by repo and Git head. Nebula should key indexes by snapshot:

```txt
old:
  orgId
  repoFullName
  gitHead

new:
  registryRepoId
  treeSnapshotId
  indexVersion
```

This is the intended identity model for future semantic retrieval against a precise snapshot, including private or environment-specific projections when policy allows.

## Planned Semantic Adapter

The first production semantic adapter should be pgvector-compatible because Astracollab already uses Postgres/pgvector patterns for code indexing.

Expected stores:

```txt
VectorIndexManifest
  snapshot_id
  index_version
  embedding_model
  chunk_count

CodeEmbeddingChunk
  manifest_id
  path
  line range
  content hash
  embedding
```

## Agent Retrieval

Agents should search by `TreeSnapshotId` or `ProjectionId`, not by Git SHA. The policy layer decides which chunks are visible to the actor and environment. Until the semantic backend is implemented, treat `vector-search` responses as experimental path/hash index results.
