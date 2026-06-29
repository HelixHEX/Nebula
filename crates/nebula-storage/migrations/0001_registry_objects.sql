CREATE TABLE IF NOT EXISTS nebula_registry_objects (
    object_kind TEXT NOT NULL,
    object_id TEXT NOT NULL,
    repository_id TEXT NOT NULL DEFAULT '__global__',
    object_json JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (repository_id, object_kind, object_id)
);

CREATE INDEX IF NOT EXISTS nebula_registry_objects_repository_idx
    ON nebula_registry_objects (repository_id, object_kind);

CREATE TABLE IF NOT EXISTS nebula_blob_metadata (
    algorithm TEXT NOT NULL,
    digest TEXT NOT NULL,
    blob_id TEXT NOT NULL,
    repository_id TEXT NOT NULL DEFAULT '__global__',
    size_bytes BIGINT NOT NULL,
    media_type TEXT,
    visibility JSONB NOT NULL,
    object_path TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (repository_id, algorithm, digest)
);

CREATE TABLE IF NOT EXISTS nebula_vector_jobs (
    job_id TEXT PRIMARY KEY,
    repository_id TEXT NOT NULL,
    snapshot_id TEXT NOT NULL,
    projection_id TEXT,
    state TEXT NOT NULL,
    worker_kind TEXT NOT NULL,
    manifest_id TEXT,
    job_json JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS nebula_idempotency_keys (
    idempotency_key TEXT NOT NULL,
    repository_id TEXT NOT NULL DEFAULT '__global__',
    object_kind TEXT NOT NULL,
    object_id TEXT NOT NULL,
    response_json JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (repository_id, idempotency_key)
);

CREATE TABLE IF NOT EXISTS nebula_ref_leases (
    repository_id TEXT NOT NULL,
    ref_name TEXT NOT NULL,
    expected_target JSONB,
    next_target JSONB NOT NULL,
    lease_token TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (repository_id, ref_name, lease_token)
);

CREATE TABLE IF NOT EXISTS nebula_sync_chunk_manifests (
    repository_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    manifest_json JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (repository_id, session_id)
);

CREATE TABLE IF NOT EXISTS nebula_registry_transactions (
    transaction_id TEXT PRIMARY KEY,
    repository_id TEXT,
    idempotency_key TEXT,
    state TEXT NOT NULL,
    transaction_json JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    committed_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS nebula_registry_mutation_audits (
    audit_id BIGSERIAL PRIMARY KEY,
    transaction_id TEXT NOT NULL,
    repository_id TEXT,
    action TEXT NOT NULL,
    audit_json JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS nebula_staged_blobs (
    staging_key TEXT PRIMARY KEY,
    repository_id TEXT,
    object_path TEXT NOT NULL,
    size_bytes BIGINT NOT NULL,
    checksum TEXT NOT NULL,
    state TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    promoted_at TIMESTAMPTZ
);
