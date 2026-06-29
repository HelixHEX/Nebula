use async_trait::async_trait;
use bytes::Bytes;
use futures::{StreamExt, TryStreamExt};
use nebula_core::{
    BlobStore, ChangeSet, ChangeSetId, CodeEmbeddingChunk, ContentBlob, ContentHash, MetadataStore,
    NebulaError, NebulaResult, Proposal, ProposalId, Ref, RegistryStore, RegistryTransaction,
    RegistryTransactionResult, RepositoryId, TreeSnapshot, TreeSnapshotId, VectorIndexManifest,
    VectorIndexManifestId, VectorIndexStore,
};
use object_store::{
    ObjectStore, WriteMultipart,
    aws::{AmazonS3, AmazonS3Builder},
    path::Path as ObjectPath,
    signer::Signer,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::{
    fs,
    path::{Path, PathBuf},
    pin::Pin,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::io::AsyncReadExt;
use url::Url;

const GLOBAL_REPOSITORY_SCOPE: &str = "__global__";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum MetadataBackend {
    File { root: PathBuf },
    Postgres { database_url: String },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum BlobBackend {
    File { root: PathBuf },
    ObjectStore { url: String },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum VectorBackend {
    Disabled,
    PgVector { database_url: String },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DurableStorageConfig {
    pub metadata: MetadataBackend,
    pub blobs: BlobBackend,
    pub vectors: VectorBackend,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MigrationPlan {
    pub backend: MetadataBackend,
    pub migrations_table: String,
    pub required_migrations: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BackupPlan {
    pub metadata_export_uri: String,
    pub blob_export_uri: String,
    pub vector_export_uri: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RestorePlan {
    pub metadata_import_uri: String,
    pub blob_import_uri: String,
    pub vector_import_uri: Option<String>,
    pub verify_checksums: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RetentionPlan {
    pub idempotency_key_retention_days: u32,
    pub ref_lease_retention_days: u32,
    pub staged_blob_retention_hours: u32,
    pub sync_artifact_retention_hours: u32,
    pub vector_job_retention_days: u32,
    pub deploy_handoff_retention_days: u32,
    pub authorization_audit_retention_days: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RetentionCleanupReport {
    pub checked_at_unix_ms: u64,
    pub dry_run: bool,
    pub plan: RetentionPlan,
    pub expired_idempotency_keys: u64,
    pub expired_ref_leases: u64,
    pub expired_staged_blobs: u64,
    pub expired_sync_artifacts: u64,
    pub expired_vector_jobs: u64,
    pub expired_deploy_handoffs: u64,
    pub expired_authorization_audits: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ConsistencyCheckReport {
    pub checked_at_unix_ms: u64,
    pub required_blob_count: usize,
    pub missing: Vec<ContentHash>,
    pub orphaned_paths: Vec<String>,
    pub dry_run: bool,
    pub deleted_orphans: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DrillValidationCheck {
    pub name: String,
    pub passed: bool,
    pub detail: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RestoreDrillReport {
    pub started_at_unix_ms: u64,
    pub restored_at_unix_ms: Option<u64>,
    pub validated_at_unix_ms: Option<u64>,
    pub rto_ms: Option<u64>,
    pub rpo_ms: Option<u64>,
    pub backup_id: Option<String>,
    pub target: String,
    pub tool: String,
    pub dry_run: bool,
    pub operator: Option<String>,
    pub outcome: String,
    pub validation_checks: Vec<DrillValidationCheck>,
    pub follow_up_actions: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BackupDrillReport {
    pub started_at_unix_ms: u64,
    pub validated_at_unix_ms: Option<u64>,
    pub tool: String,
    pub dry_run: bool,
    pub operator: Option<String>,
    pub outcome: String,
    pub validation_checks: Vec<DrillValidationCheck>,
    pub follow_up_actions: Vec<String>,
}

pub fn production_migration_plan(backend: MetadataBackend) -> MigrationPlan {
    MigrationPlan {
        backend,
        migrations_table: "_sqlx_migrations".to_string(),
        required_migrations: vec!["0001_registry_objects".to_string()],
    }
}

pub fn production_backup_plan(
    metadata_export_uri: impl Into<String>,
    blob_export_uri: impl Into<String>,
    vector_export_uri: Option<String>,
) -> BackupPlan {
    BackupPlan {
        metadata_export_uri: metadata_export_uri.into(),
        blob_export_uri: blob_export_uri.into(),
        vector_export_uri,
    }
}

pub fn production_restore_plan(
    metadata_import_uri: impl Into<String>,
    blob_import_uri: impl Into<String>,
    vector_import_uri: Option<String>,
) -> RestorePlan {
    RestorePlan {
        metadata_import_uri: metadata_import_uri.into(),
        blob_import_uri: blob_import_uri.into(),
        vector_import_uri,
        verify_checksums: true,
    }
}

pub fn default_retention_plan() -> RetentionPlan {
    RetentionPlan {
        idempotency_key_retention_days: 7,
        ref_lease_retention_days: 1,
        staged_blob_retention_hours: 24,
        sync_artifact_retention_hours: 24,
        vector_job_retention_days: 14,
        deploy_handoff_retention_days: 30,
        authorization_audit_retention_days: 90,
    }
}

pub fn backup_drill_report(
    tool: impl Into<String>,
    dry_run: bool,
    operator: Option<String>,
) -> BackupDrillReport {
    let now = now_unix_ms();
    BackupDrillReport {
        started_at_unix_ms: now,
        validated_at_unix_ms: dry_run.then_some(now),
        tool: tool.into(),
        dry_run,
        operator,
        outcome: if dry_run {
            "experimental_dry_run_requires_external_backup_tool".to_string()
        } else {
            "experimental_configured_external_backup_tool_invocation_required".to_string()
        },
        validation_checks: vec![DrillValidationCheck {
            name: "backup_tool_configured".to_string(),
            passed: dry_run,
            detail: "Nebula orchestrates provider-grade backup tools; it does not implement a custom database backup engine.".to_string(),
        }],
        follow_up_actions: vec![
            "Configure managed snapshots, WAL-G, pgBackRest, or provider-native PITR before execute mode.".to_string(),
        ],
    }
}

pub fn restore_drill_report(
    tool: impl Into<String>,
    target: impl Into<String>,
    backup_id: Option<String>,
    dry_run: bool,
    operator: Option<String>,
) -> RestoreDrillReport {
    let now = now_unix_ms();
    RestoreDrillReport {
        started_at_unix_ms: now,
        restored_at_unix_ms: dry_run.then_some(now),
        validated_at_unix_ms: dry_run.then_some(now),
        rto_ms: dry_run.then_some(0),
        rpo_ms: None,
        backup_id,
        target: target.into(),
        tool: tool.into(),
        dry_run,
        operator,
        outcome: if dry_run {
            "experimental_dry_run_restore_drill_plan".to_string()
        } else {
            "experimental_restore_drill_requires_configured_external_tool_execution".to_string()
        },
        validation_checks: vec![
            DrillValidationCheck {
                name: "isolated_target_required".to_string(),
                passed: dry_run,
                detail: "Restore drills must run against a staging database/object prefix, never a live production target.".to_string(),
            },
            DrillValidationCheck {
                name: "post_restore_consistency_required".to_string(),
                passed: dry_run,
                detail: "A successful drill must pass metadata, object consistency, readiness, and application smoke checks.".to_string(),
            },
        ],
        follow_up_actions: vec![
            "Run monthly critical-metadata restore drills and record measured RTO/RPO.".to_string(),
            "Treat failed restore drills as release-blocking until remediated or explicitly accepted.".to_string(),
        ],
    }
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or_default()
}

#[derive(Clone, Debug)]
pub struct FileBlobStore {
    root: PathBuf,
}

impl FileBlobStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn path(&self, hash: &ContentHash) -> PathBuf {
        self.root.join(hash.object_path())
    }
}

#[async_trait]
impl BlobStore for FileBlobStore {
    async fn put(&self, hash: &ContentHash, bytes: &[u8]) -> NebulaResult<()> {
        let path = self.path(hash);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(storage_error)?;
        }
        if !path.exists() {
            fs::write(path, bytes).map_err(storage_error)?;
        }
        Ok(())
    }

    async fn get(&self, hash: &ContentHash) -> NebulaResult<Vec<u8>> {
        fs::read(self.path(hash)).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                NebulaError::NotFound(format!("blob {}:{}", hash.algorithm, hash.digest))
            } else {
                storage_error(error)
            }
        })
    }

    async fn exists(&self, hash: &ContentHash) -> NebulaResult<bool> {
        Ok(self.path(hash).exists())
    }

    async fn put_stream(
        &self,
        hash: &ContentHash,
        mut stream: Pin<Box<dyn futures::Stream<Item = NebulaResult<Bytes>> + Send>>,
    ) -> NebulaResult<u64> {
        let destination = self.path(hash);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent).map_err(storage_error)?;
        }
        if destination.exists() {
            return Ok(fs::metadata(destination).map_err(storage_error)?.len());
        }
        let tmp_path = self
            .root
            .join(format!(".upload-{}-{}", hash.algorithm, hash.digest));
        let mut file = tokio::fs::File::create(&tmp_path)
            .await
            .map_err(storage_error)?;
        let mut hasher = Sha256::new();
        let mut size_bytes = 0u64;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            hasher.update(&chunk);
            size_bytes += chunk.len() as u64;
            tokio::io::AsyncWriteExt::write_all(&mut file, &chunk)
                .await
                .map_err(storage_error)?;
        }
        file.sync_all().await.map_err(storage_error)?;
        drop(file);
        let actual_hash = ContentHash {
            algorithm: "sha256".to_string(),
            digest: hex::encode(hasher.finalize()),
        };
        if &actual_hash != hash {
            let _ = fs::remove_file(&tmp_path);
            return Err(NebulaError::InvalidOperation(format!(
                "blob checksum mismatch: expected {}:{}, got {}:{}",
                hash.algorithm, hash.digest, actual_hash.algorithm, actual_hash.digest
            )));
        }
        fs::rename(tmp_path, destination).map_err(storage_error)?;
        Ok(size_bytes)
    }

    async fn put_from_path(&self, hash: &ContentHash, path: &Path) -> NebulaResult<u64> {
        let (actual_hash, size_bytes) =
            ContentHash::sha256_reader(fs::File::open(path).map_err(storage_error)?)
                .map_err(storage_error)?;
        if &actual_hash != hash {
            return Err(NebulaError::InvalidOperation(format!(
                "blob checksum mismatch: expected {}:{}, got {}:{}",
                hash.algorithm, hash.digest, actual_hash.algorithm, actual_hash.digest
            )));
        }
        let destination = self.path(hash);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent).map_err(storage_error)?;
        }
        if !destination.exists() {
            fs::copy(path, &destination).map_err(storage_error)?;
        }
        Ok(size_bytes)
    }

    async fn get_to_path(&self, hash: &ContentHash, path: &Path) -> NebulaResult<u64> {
        let source = self.path(hash);
        if !source.exists() {
            return Err(NebulaError::NotFound(format!(
                "blob {}:{}",
                hash.algorithm, hash.digest
            )));
        }
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(storage_error)?;
        }
        fs::copy(source, path).map_err(storage_error)?;
        let (actual_hash, size_bytes) =
            ContentHash::sha256_reader(fs::File::open(path).map_err(storage_error)?)
                .map_err(storage_error)?;
        if &actual_hash != hash {
            return Err(NebulaError::InvalidOperation(format!(
                "blob checksum mismatch: expected {}:{}, got {}:{}",
                hash.algorithm, hash.digest, actual_hash.algorithm, actual_hash.digest
            )));
        }
        Ok(size_bytes)
    }
}

#[derive(Clone, Debug)]
pub struct FileMetadataStore {
    root: PathBuf,
}

impl FileMetadataStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn object_path(&self, group: &str, id: &str) -> PathBuf {
        self.root.join(group).join(format!("{id}.json"))
    }

    fn read_json<T: for<'de> Deserialize<'de>>(&self, path: &Path) -> NebulaResult<T> {
        let content = fs::read_to_string(path).map_err(storage_error)?;
        serde_json::from_str(&content).map_err(|error| NebulaError::Storage(error.to_string()))
    }

    fn write_json<T: Serialize>(&self, path: &Path, value: &T) -> NebulaResult<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(storage_error)?;
        }
        let content = serde_json::to_string_pretty(value)
            .map_err(|error| NebulaError::Storage(error.to_string()))?;
        fs::write(path, format!("{content}\n")).map_err(storage_error)
    }
}

#[async_trait]
impl MetadataStore for FileMetadataStore {
    async fn put_snapshot(&self, snapshot: TreeSnapshot) -> NebulaResult<()> {
        self.write_json(
            &self.object_path("snapshots", snapshot.id.as_str()),
            &snapshot,
        )
    }

    async fn get_snapshot(&self, id: &TreeSnapshotId) -> NebulaResult<TreeSnapshot> {
        self.read_json(&self.object_path("snapshots", id.as_str()))
    }

    async fn put_ref(&self, reference: Ref) -> NebulaResult<()> {
        let id = format!("{}_{}", reference.repository_id.as_str(), reference.name);
        self.write_json(&self.object_path("refs", &id), &reference)
    }

    async fn get_ref_by_name(&self, repository_id: &RepositoryId, name: &str) -> NebulaResult<Ref> {
        let id = format!("{}_{}", repository_id.as_str(), name);
        self.read_json(&self.object_path("refs", &id))
    }

    async fn put_changeset(&self, changeset: ChangeSet) -> NebulaResult<()> {
        self.write_json(
            &self.object_path("changesets", changeset.id.as_str()),
            &changeset,
        )
    }

    async fn get_changeset(&self, id: &ChangeSetId) -> NebulaResult<ChangeSet> {
        self.read_json(&self.object_path("changesets", id.as_str()))
    }

    async fn put_proposal(&self, proposal: Proposal) -> NebulaResult<()> {
        self.write_json(
            &self.object_path("proposals", proposal.id.as_str()),
            &proposal,
        )
    }

    async fn get_proposal(&self, id: &ProposalId) -> NebulaResult<Proposal> {
        self.read_json(&self.object_path("proposals", id.as_str()))
    }
}

#[derive(Clone, Debug)]
pub struct FileVectorIndexStore {
    root: PathBuf,
}

impl FileVectorIndexStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn manifest_path(&self, manifest_id: &VectorIndexManifestId) -> PathBuf {
        self.root
            .join("manifests")
            .join(format!("{}.json", manifest_id.as_str()))
    }

    fn chunks_path(&self, manifest_id: &VectorIndexManifestId) -> PathBuf {
        self.root
            .join("chunks")
            .join(format!("{}.json", manifest_id.as_str()))
    }
}

#[async_trait]
impl VectorIndexStore for FileVectorIndexStore {
    async fn put_manifest(&self, manifest: VectorIndexManifest) -> NebulaResult<()> {
        let path = self.manifest_path(&manifest.id);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(storage_error)?;
        }
        let content = serde_json::to_string_pretty(&manifest)
            .map_err(|error| NebulaError::Storage(error.to_string()))?;
        fs::write(path, format!("{content}\n")).map_err(storage_error)
    }

    async fn put_chunks(
        &self,
        manifest: &VectorIndexManifest,
        chunks: Vec<CodeEmbeddingChunk>,
    ) -> NebulaResult<()> {
        if chunks.iter().any(|chunk| chunk.manifest_id != manifest.id) {
            return Err(NebulaError::InvalidOperation(
                "vector chunk manifest mismatch".to_string(),
            ));
        }
        let path = self.chunks_path(&manifest.id);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(storage_error)?;
        }
        let content = serde_json::to_string_pretty(&chunks)
            .map_err(|error| NebulaError::Storage(error.to_string()))?;
        fs::write(path, format!("{content}\n")).map_err(storage_error)
    }

    async fn get_manifest_for_snapshot(
        &self,
        snapshot_id: &TreeSnapshotId,
    ) -> NebulaResult<Option<VectorIndexManifest>> {
        let root = self.root.join("manifests");
        if !root.exists() {
            return Ok(None);
        }
        for entry in fs::read_dir(root).map_err(storage_error)? {
            let entry = entry.map_err(storage_error)?;
            if entry.path().extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            let manifest: VectorIndexManifest =
                serde_json::from_str(&fs::read_to_string(entry.path()).map_err(storage_error)?)
                    .map_err(|error| NebulaError::Storage(error.to_string()))?;
            if &manifest.snapshot_id == snapshot_id {
                return Ok(Some(manifest));
            }
        }
        Ok(None)
    }

    async fn get_manifest(
        &self,
        repository_id: &RepositoryId,
        manifest_id: &VectorIndexManifestId,
    ) -> NebulaResult<Option<VectorIndexManifest>> {
        let path = self.manifest_path(manifest_id);
        if !path.exists() {
            return Ok(None);
        }
        let manifest: VectorIndexManifest =
            serde_json::from_str(&fs::read_to_string(path).map_err(storage_error)?)
                .map_err(|error| NebulaError::Storage(error.to_string()))?;
        Ok((manifest.repository_id == *repository_id).then_some(manifest))
    }

    async fn get_chunks(
        &self,
        repository_id: &RepositoryId,
        manifest_id: &VectorIndexManifestId,
    ) -> NebulaResult<Vec<CodeEmbeddingChunk>> {
        let Some(_) = self.get_manifest(repository_id, manifest_id).await? else {
            return Ok(Vec::new());
        };
        let path = self.chunks_path(manifest_id);
        if !path.exists() {
            return Ok(Vec::new());
        }
        serde_json::from_str(&fs::read_to_string(path).map_err(storage_error)?)
            .map_err(|error| NebulaError::Storage(error.to_string()))
    }

    async fn search_chunks(
        &self,
        repository_id: &RepositoryId,
        manifest_id: &VectorIndexManifestId,
        query: &str,
        top_k: usize,
    ) -> NebulaResult<Vec<CodeEmbeddingChunk>> {
        let query = query.to_lowercase();
        Ok(self
            .get_chunks(repository_id, manifest_id)
            .await?
            .into_iter()
            .filter(|chunk| query.is_empty() || chunk.path.to_lowercase().contains(&query))
            .take(top_k)
            .collect())
    }
}

#[derive(Clone, Debug)]
pub struct PostgresMetadataStore {
    pool: PgPool,
}

#[derive(Clone, Debug)]
pub struct ObjectBlobStore {
    store: Arc<dyn ObjectStore>,
    s3_signer: Option<Arc<AmazonS3>>,
    prefix: ObjectPath,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ObjectStoreConsistencyReport {
    pub missing: Vec<ContentHash>,
    pub orphaned_paths: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct PgVectorManifestStore {
    pool: PgPool,
}

impl PostgresMetadataStore {
    pub async fn connect(database_url: &str) -> NebulaResult<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect(database_url)
            .await
            .map_err(sqlx_error)?;
        Ok(Self { pool })
    }

    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn run_migrations(&self) -> NebulaResult<()> {
        sqlx::migrate!("./migrations")
            .run(&self.pool)
            .await
            .map_err(|error| NebulaError::Storage(error.to_string()))
    }

    pub async fn ready(&self) -> NebulaResult<()> {
        sqlx::query("SELECT 1")
            .execute(&self.pool)
            .await
            .map_err(sqlx_error)?;
        Ok(())
    }

    pub async fn required_blob_hashes(&self) -> NebulaResult<Vec<ContentHash>> {
        let rows = sqlx::query_scalar::<_, serde_json::Value>(
            r#"
            SELECT object_json
            FROM nebula_registry_objects
            WHERE object_kind = 'blob'
            "#,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(sqlx_error)?;
        let mut hashes = Vec::new();
        for value in rows {
            let blob: ContentBlob = serde_json::from_value(value)
                .map_err(|error| NebulaError::Storage(error.to_string()))?;
            hashes.push(blob.hash);
        }
        hashes.sort();
        hashes.dedup();
        Ok(hashes)
    }

    pub async fn retention_cleanup_report(
        &self,
        plan: RetentionPlan,
        dry_run: bool,
    ) -> NebulaResult<RetentionCleanupReport> {
        let expired_idempotency_keys = self
            .count_or_delete_older_than(
                "nebula_idempotency_keys",
                "created_at",
                plan.idempotency_key_retention_days,
                "days",
                dry_run,
            )
            .await?;
        let expired_ref_leases = self
            .count_or_delete_older_than(
                "nebula_ref_leases",
                "created_at",
                plan.ref_lease_retention_days,
                "days",
                dry_run,
            )
            .await?;
        let expired_staged_blobs = self
            .count_or_delete_older_than(
                "nebula_staged_blobs",
                "created_at",
                plan.staged_blob_retention_hours,
                "hours",
                dry_run,
            )
            .await?;
        let expired_sync_artifacts = self
            .count_or_delete_registry_kind_older_than(
                "sync_chunk",
                plan.sync_artifact_retention_hours,
                "hours",
                dry_run,
            )
            .await?
            + self
                .count_or_delete_registry_kind_older_than(
                    "sync_bundle",
                    plan.sync_artifact_retention_hours,
                    "hours",
                    dry_run,
                )
                .await?
            + self
                .count_or_delete_registry_kind_older_than(
                    "chunk_manifest",
                    plan.sync_artifact_retention_hours,
                    "hours",
                    dry_run,
                )
                .await?;
        let expired_vector_jobs = self
            .count_or_delete_older_than(
                "nebula_vector_jobs",
                "created_at",
                plan.vector_job_retention_days,
                "days",
                dry_run,
            )
            .await?;
        let expired_deploy_handoffs = self
            .count_or_delete_registry_kind_older_than(
                "deploy_intent",
                plan.deploy_handoff_retention_days,
                "days",
                dry_run,
            )
            .await?;
        let expired_authorization_audits = self
            .count_or_delete_older_than(
                "nebula_registry_mutation_audits",
                "created_at",
                plan.authorization_audit_retention_days,
                "days",
                dry_run,
            )
            .await?;
        Ok(RetentionCleanupReport {
            checked_at_unix_ms: now_unix_ms(),
            dry_run,
            plan,
            expired_idempotency_keys,
            expired_ref_leases,
            expired_staged_blobs,
            expired_sync_artifacts,
            expired_vector_jobs,
            expired_deploy_handoffs,
            expired_authorization_audits,
        })
    }

    async fn count_or_delete_older_than(
        &self,
        table: &str,
        timestamp_column: &str,
        amount: u32,
        unit: &str,
        dry_run: bool,
    ) -> NebulaResult<u64> {
        let sql = if dry_run {
            format!(
                "SELECT COUNT(*)::BIGINT FROM {table} WHERE {timestamp_column} < NOW() - ($1::INT * INTERVAL '1 {unit}')"
            )
        } else {
            format!(
                "WITH deleted AS (DELETE FROM {table} WHERE {timestamp_column} < NOW() - ($1::INT * INTERVAL '1 {unit}') RETURNING 1) SELECT COUNT(*)::BIGINT FROM deleted"
            )
        };
        let count = sqlx::query_scalar::<_, i64>(&sql)
            .bind(amount as i32)
            .fetch_one(&self.pool)
            .await
            .map_err(sqlx_error)?;
        Ok(count as u64)
    }

    async fn count_or_delete_registry_kind_older_than(
        &self,
        kind: &str,
        amount: u32,
        unit: &str,
        dry_run: bool,
    ) -> NebulaResult<u64> {
        let sql = if dry_run {
            "SELECT COUNT(*)::BIGINT FROM nebula_registry_objects WHERE object_kind = $1 AND created_at < NOW() - ($2::INT * INTERVAL '1 hour')"
        } else {
            "WITH deleted AS (DELETE FROM nebula_registry_objects WHERE object_kind = $1 AND created_at < NOW() - ($2::INT * INTERVAL '1 hour') RETURNING 1) SELECT COUNT(*)::BIGINT FROM deleted"
        };
        let multiplier = if unit == "days" { 24 } else { 1 };
        let count = sqlx::query_scalar::<_, i64>(sql)
            .bind(kind)
            .bind((amount * multiplier) as i32)
            .fetch_one(&self.pool)
            .await
            .map_err(sqlx_error)?;
        Ok(count as u64)
    }

    async fn put_object<T: Serialize + Send + Sync>(
        &self,
        kind: &str,
        id: &str,
        repository_id: Option<&RepositoryId>,
        value: &T,
    ) -> NebulaResult<()> {
        let json = serde_json::to_value(value).map_err(serde_error)?;
        sqlx::query(
            r#"
            INSERT INTO nebula_registry_objects (object_kind, object_id, repository_id, object_json)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (repository_id, object_kind, object_id)
            DO UPDATE SET
                repository_id = EXCLUDED.repository_id,
                object_json = EXCLUDED.object_json,
                updated_at = NOW()
            "#,
        )
        .bind(kind)
        .bind(id)
        .bind(
            repository_id
                .map(RepositoryId::as_str)
                .unwrap_or(GLOBAL_REPOSITORY_SCOPE),
        )
        .bind(json)
        .execute(&self.pool)
        .await
        .map_err(sqlx_error)?;
        Ok(())
    }

    async fn get_object<T: for<'de> Deserialize<'de>>(
        &self,
        kind: &str,
        id: &str,
    ) -> NebulaResult<T> {
        let values: Vec<serde_json::Value> = sqlx::query_scalar(
            r#"
            SELECT object_json
            FROM nebula_registry_objects
            WHERE object_kind = $1 AND object_id = $2
            LIMIT 2
            "#,
        )
        .bind(kind)
        .bind(id)
        .fetch_all(&self.pool)
        .await
        .map_err(sqlx_error)?;
        let value = match values.as_slice() {
            [] => return Err(NebulaError::NotFound(format!("{kind} {id}"))),
            [value] => value.clone(),
            _ => {
                return Err(NebulaError::InvalidOperation(format!(
                    "unscoped lookup for {kind} {id} is ambiguous"
                )));
            }
        };
        serde_json::from_value(value).map_err(serde_error)
    }
}

#[async_trait]
impl RegistryStore for PostgresMetadataStore {
    async fn put_repository_record(
        &self,
        repository_id: &RepositoryId,
        value: serde_json::Value,
    ) -> NebulaResult<()> {
        self.put_object(
            "repository",
            repository_id.as_str(),
            Some(repository_id),
            &value,
        )
        .await
    }

    async fn get_repository_record(
        &self,
        repository_id: &RepositoryId,
    ) -> NebulaResult<serde_json::Value> {
        self.get_object("repository", repository_id.as_str()).await
    }

    async fn put_resource(
        &self,
        repository_id: Option<&RepositoryId>,
        kind: &str,
        id: &str,
        value: serde_json::Value,
    ) -> NebulaResult<()> {
        self.put_object(kind, id, repository_id, &value).await
    }

    async fn get_resource(&self, kind: &str, id: &str) -> NebulaResult<serde_json::Value> {
        self.get_object(kind, id).await
    }

    async fn get_resource_scoped(
        &self,
        repository_id: Option<&RepositoryId>,
        kind: &str,
        id: &str,
    ) -> NebulaResult<serde_json::Value> {
        let value: serde_json::Value = sqlx::query_scalar(
            r#"
            SELECT object_json
            FROM nebula_registry_objects
            WHERE object_kind = $1
              AND object_id = $2
              AND repository_id = $3
            "#,
        )
        .bind(kind)
        .bind(id)
        .bind(
            repository_id
                .map(RepositoryId::as_str)
                .unwrap_or(GLOBAL_REPOSITORY_SCOPE),
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(sqlx_error)?
        .ok_or_else(|| NebulaError::NotFound(format!("{kind} {id}")))?;
        Ok(value)
    }

    async fn list_resources(&self, kind: &str) -> NebulaResult<Vec<serde_json::Value>> {
        sqlx::query_scalar(
            r#"
            SELECT object_json
            FROM nebula_registry_objects
            WHERE object_kind = $1
            ORDER BY created_at ASC
            "#,
        )
        .bind(kind)
        .fetch_all(&self.pool)
        .await
        .map_err(sqlx_error)
    }

    async fn list_resources_scoped(
        &self,
        repository_id: Option<&RepositoryId>,
        kind: &str,
    ) -> NebulaResult<Vec<serde_json::Value>> {
        sqlx::query_scalar(
            r#"
            SELECT object_json
            FROM nebula_registry_objects
            WHERE object_kind = $1
              AND repository_id = $2
            ORDER BY created_at ASC
            "#,
        )
        .bind(kind)
        .bind(
            repository_id
                .map(RepositoryId::as_str)
                .unwrap_or(GLOBAL_REPOSITORY_SCOPE),
        )
        .fetch_all(&self.pool)
        .await
        .map_err(sqlx_error)
    }

    async fn delete_resource(
        &self,
        repository_id: Option<&RepositoryId>,
        kind: &str,
        id: &str,
    ) -> NebulaResult<()> {
        sqlx::query(
            r#"
            DELETE FROM nebula_registry_objects
            WHERE repository_id = $1 AND object_kind = $2 AND object_id = $3
            "#,
        )
        .bind(
            repository_id
                .map(RepositoryId::as_str)
                .unwrap_or(GLOBAL_REPOSITORY_SCOPE),
        )
        .bind(kind)
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(sqlx_error)?;
        Ok(())
    }

    async fn put_resource_idempotent(
        &self,
        repository_id: Option<&RepositoryId>,
        kind: &str,
        id: &str,
        idempotency_key: &str,
        value: serde_json::Value,
    ) -> NebulaResult<serde_json::Value> {
        let repository_scope = repository_id
            .map(RepositoryId::as_str)
            .unwrap_or(GLOBAL_REPOSITORY_SCOPE);
        let mut tx = self.pool.begin().await.map_err(sqlx_error)?;
        let inserted_key = sqlx::query(
            r#"
            INSERT INTO nebula_idempotency_keys
                (idempotency_key, repository_id, object_kind, object_id, response_json)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (repository_id, idempotency_key) DO NOTHING
            "#,
        )
        .bind(idempotency_key)
        .bind(repository_scope)
        .bind(kind)
        .bind(id)
        .bind(&value)
        .execute(&mut *tx)
        .await
        .map_err(sqlx_error)?
        .rows_affected()
            == 1;
        if !inserted_key {
            let existing: (String, String, serde_json::Value) = sqlx::query_as(
                r#"
                SELECT object_kind, object_id, response_json
                FROM nebula_idempotency_keys
                WHERE repository_id = $1 AND idempotency_key = $2
                FOR UPDATE
                "#,
            )
            .bind(repository_scope)
            .bind(idempotency_key)
            .fetch_one(&mut *tx)
            .await
            .map_err(sqlx_error)?;
            if existing.0 != kind || existing.1 != id || existing.2 != value {
                return Err(NebulaError::InvalidOperation(
                    "idempotency key reused with a different request".to_string(),
                ));
            }
            tx.commit().await.map_err(sqlx_error)?;
            return Ok(existing.2);
        }

        sqlx::query(
            r#"
            INSERT INTO nebula_registry_objects (object_kind, object_id, repository_id, object_json)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (repository_id, object_kind, object_id)
            DO UPDATE SET
                repository_id = EXCLUDED.repository_id,
                object_json = EXCLUDED.object_json,
                updated_at = NOW()
            "#,
        )
        .bind(kind)
        .bind(id)
        .bind(repository_scope)
        .bind(&value)
        .execute(&mut *tx)
        .await
        .map_err(sqlx_error)?;
        tx.commit().await.map_err(sqlx_error)?;
        Ok(value)
    }

    async fn compare_and_swap_ref(
        &self,
        repository_id: &RepositoryId,
        name: &str,
        expected_target: Option<serde_json::Value>,
        next_ref: serde_json::Value,
    ) -> NebulaResult<bool> {
        let id = format!("{}_{}", repository_id.as_str(), name);
        let mut tx = self.pool.begin().await.map_err(sqlx_error)?;
        if expected_target.is_none() {
            let result = sqlx::query(
                r#"
                INSERT INTO nebula_registry_objects (object_kind, object_id, repository_id, object_json)
                VALUES ('ref', $1, $2, $3)
                ON CONFLICT (repository_id, object_kind, object_id) DO NOTHING
                "#,
            )
            .bind(&id)
            .bind(repository_id.as_str())
            .bind(&next_ref)
            .execute(&mut *tx)
            .await
            .map_err(sqlx_error)?;
            tx.commit().await.map_err(sqlx_error)?;
            return Ok(result.rows_affected() == 1);
        }
        let current: Option<serde_json::Value> = sqlx::query_scalar(
            r#"
            SELECT object_json->'target'
            FROM nebula_registry_objects
            WHERE repository_id = $2 AND object_kind = 'ref' AND object_id = $1
            FOR UPDATE
            "#,
        )
        .bind(&id)
        .bind(repository_id.as_str())
        .fetch_optional(&mut *tx)
        .await
        .map_err(sqlx_error)?;
        if current != expected_target {
            return Ok(false);
        }
        sqlx::query(
            r#"
            INSERT INTO nebula_registry_objects (object_kind, object_id, repository_id, object_json)
            VALUES ('ref', $1, $2, $3)
            ON CONFLICT (repository_id, object_kind, object_id)
            DO UPDATE SET
                repository_id = EXCLUDED.repository_id,
                object_json = EXCLUDED.object_json,
                updated_at = NOW()
            "#,
        )
        .bind(&id)
        .bind(repository_id.as_str())
        .bind(&next_ref)
        .execute(&mut *tx)
        .await
        .map_err(sqlx_error)?;
        tx.commit().await.map_err(sqlx_error)?;
        Ok(true)
    }

    async fn commit_transaction(
        &self,
        transaction: RegistryTransaction,
    ) -> NebulaResult<RegistryTransactionResult> {
        let transaction_repository_scope = transaction
            .repository_id
            .as_ref()
            .map(RepositoryId::as_str)
            .unwrap_or(GLOBAL_REPOSITORY_SCOPE);
        let result = RegistryTransactionResult {
            transaction_id: transaction.id.clone(),
            committed: true,
            mutation_count: transaction.mutations.len() + transaction.ref_updates.len(),
        };
        let result_json = serde_json::to_value(&result).map_err(serde_error)?;
        let transaction_json = serde_json::to_value(&transaction).map_err(serde_error)?;
        let mut tx = self.pool.begin().await.map_err(sqlx_error)?;
        if let Some(idempotency_key) = &transaction.idempotency_key {
            let inserted_key = sqlx::query(
                r#"
                INSERT INTO nebula_idempotency_keys
                    (idempotency_key, repository_id, object_kind, object_id, response_json)
                VALUES ($1, $2, 'transaction', $3, $4)
                ON CONFLICT (repository_id, idempotency_key) DO NOTHING
                "#,
            )
            .bind(idempotency_key)
            .bind(transaction_repository_scope)
            .bind(&transaction.id)
            .bind(&result_json)
            .execute(&mut *tx)
            .await
            .map_err(sqlx_error)?
            .rows_affected()
                == 1;
            if !inserted_key {
                let existing: (String, String, serde_json::Value) = sqlx::query_as(
                    r#"
                    SELECT object_kind, object_id, response_json
                    FROM nebula_idempotency_keys
                    WHERE repository_id = $1 AND idempotency_key = $2
                    FOR UPDATE
                    "#,
                )
                .bind(transaction_repository_scope)
                .bind(idempotency_key)
                .fetch_one(&mut *tx)
                .await
                .map_err(sqlx_error)?;
                if existing.0 != "transaction"
                    || existing.1 != transaction.id
                    || existing.2 != result_json
                {
                    return Err(NebulaError::InvalidOperation(
                        "idempotency key reused with a different transaction".to_string(),
                    ));
                }
                tx.commit().await.map_err(sqlx_error)?;
                return serde_json::from_value(existing.2).map_err(serde_error);
            }
        }

        for ref_update in &transaction.ref_updates {
            let id = format!("{}_{}", ref_update.repository_id.as_str(), ref_update.name);
            let current: Option<serde_json::Value> = sqlx::query_scalar(
                r#"
                SELECT object_json->'target'
                FROM nebula_registry_objects
                WHERE repository_id = $2 AND object_kind = 'ref' AND object_id = $1
                FOR UPDATE
                "#,
            )
            .bind(&id)
            .bind(ref_update.repository_id.as_str())
            .fetch_optional(&mut *tx)
            .await
            .map_err(sqlx_error)?;
            if current != ref_update.expected_target {
                return Err(NebulaError::InvalidOperation(format!(
                    "ref lease check failed for {}",
                    ref_update.name
                )));
            }
        }

        sqlx::query(
            r#"
            INSERT INTO nebula_registry_transactions
                (transaction_id, repository_id, idempotency_key, state, transaction_json)
            VALUES ($1, $2, $3, 'pending', $4)
            ON CONFLICT (transaction_id)
            DO UPDATE SET transaction_json = EXCLUDED.transaction_json
            "#,
        )
        .bind(&transaction.id)
        .bind(transaction_repository_scope)
        .bind(transaction.idempotency_key.as_deref())
        .bind(&transaction_json)
        .execute(&mut *tx)
        .await
        .map_err(sqlx_error)?;

        for mutation in &transaction.mutations {
            sqlx::query(
                r#"
                INSERT INTO nebula_registry_objects (object_kind, object_id, repository_id, object_json)
                VALUES ($1, $2, $3, $4)
                ON CONFLICT (repository_id, object_kind, object_id)
                DO UPDATE SET
                    repository_id = EXCLUDED.repository_id,
                    object_json = EXCLUDED.object_json,
                    updated_at = NOW()
                "#,
            )
            .bind(&mutation.kind)
            .bind(&mutation.id)
            .bind(
                mutation
                    .repository_id
                    .as_ref()
                    .map(RepositoryId::as_str)
                    .unwrap_or(GLOBAL_REPOSITORY_SCOPE),
            )
            .bind(&mutation.value)
            .execute(&mut *tx)
            .await
            .map_err(sqlx_error)?;
        }

        for ref_update in &transaction.ref_updates {
            let id = format!("{}_{}", ref_update.repository_id.as_str(), ref_update.name);
            if ref_update.expected_target.is_none() {
                sqlx::query(
                    r#"
                    INSERT INTO nebula_registry_objects (object_kind, object_id, repository_id, object_json)
                    VALUES ('ref', $1, $2, $3)
                    ON CONFLICT (repository_id, object_kind, object_id)
                    DO UPDATE SET
                        repository_id = EXCLUDED.repository_id,
                        object_json = EXCLUDED.object_json,
                        updated_at = NOW()
                    "#,
                )
                .bind(&id)
                .bind(ref_update.repository_id.as_str())
                .bind(&ref_update.next_ref)
                .execute(&mut *tx)
                .await
                .map_err(sqlx_error)?;
            } else {
                sqlx::query(
                    r#"
                    INSERT INTO nebula_registry_objects (object_kind, object_id, repository_id, object_json)
                    VALUES ('ref', $1, $2, $3)
                    ON CONFLICT (repository_id, object_kind, object_id)
                    DO UPDATE SET
                        repository_id = EXCLUDED.repository_id,
                        object_json = EXCLUDED.object_json,
                        updated_at = NOW()
                    "#,
                )
                .bind(&id)
                .bind(ref_update.repository_id.as_str())
                .bind(&ref_update.next_ref)
                .execute(&mut *tx)
                .await
                .map_err(sqlx_error)?;
            }
        }

        sqlx::query(
            r#"
            INSERT INTO nebula_registry_mutation_audits
                (transaction_id, repository_id, action, audit_json)
            VALUES ($1, $2, $3, $4)
            "#,
        )
        .bind(&transaction.id)
        .bind(transaction_repository_scope)
        .bind(&transaction.audit.action)
        .bind(serde_json::to_value(&transaction.audit).map_err(serde_error)?)
        .execute(&mut *tx)
        .await
        .map_err(sqlx_error)?;
        sqlx::query(
            r#"
            UPDATE nebula_registry_transactions
            SET state = 'committed', committed_at = NOW()
            WHERE transaction_id = $1
            "#,
        )
        .bind(&transaction.id)
        .execute(&mut *tx)
        .await
        .map_err(sqlx_error)?;
        tx.commit().await.map_err(sqlx_error)?;
        Ok(result)
    }
}

#[async_trait]
impl MetadataStore for PostgresMetadataStore {
    async fn put_snapshot(&self, snapshot: TreeSnapshot) -> NebulaResult<()> {
        self.put_object(
            "snapshot",
            snapshot.id.as_str(),
            Some(&snapshot.repository_id),
            &snapshot,
        )
        .await
    }

    async fn get_snapshot(&self, id: &TreeSnapshotId) -> NebulaResult<TreeSnapshot> {
        self.get_object("snapshot", id.as_str()).await
    }

    async fn put_ref(&self, reference: Ref) -> NebulaResult<()> {
        let id = format!("{}_{}", reference.repository_id.as_str(), reference.name);
        self.put_object("ref", &id, Some(&reference.repository_id), &reference)
            .await
    }

    async fn get_ref_by_name(&self, repository_id: &RepositoryId, name: &str) -> NebulaResult<Ref> {
        let id = format!("{}_{}", repository_id.as_str(), name);
        self.get_object("ref", &id).await
    }

    async fn put_changeset(&self, changeset: ChangeSet) -> NebulaResult<()> {
        self.put_object(
            "changeset",
            changeset.id.as_str(),
            Some(&changeset.repository_id),
            &changeset,
        )
        .await
    }

    async fn get_changeset(&self, id: &ChangeSetId) -> NebulaResult<ChangeSet> {
        self.get_object("changeset", id.as_str()).await
    }

    async fn put_proposal(&self, proposal: Proposal) -> NebulaResult<()> {
        self.put_object(
            "proposal",
            proposal.id.as_str(),
            Some(&proposal.repository_id),
            &proposal,
        )
        .await
    }

    async fn get_proposal(&self, id: &ProposalId) -> NebulaResult<Proposal> {
        self.get_object("proposal", id.as_str()).await
    }
}

impl ObjectBlobStore {
    pub fn from_url(raw_url: &str) -> NebulaResult<Self> {
        let url = Url::parse(raw_url).map_err(|error| NebulaError::Storage(error.to_string()))?;
        if url.scheme() == "s3" {
            let bucket = url
                .host_str()
                .ok_or_else(|| NebulaError::Storage("s3 URL missing bucket name".to_string()))?;
            let store = AmazonS3Builder::from_env()
                .with_bucket_name(bucket)
                .build()
                .map_err(|error| NebulaError::Storage(error.to_string()))?;
            let store = Arc::new(store);
            return Ok(Self {
                store: store.clone(),
                s3_signer: Some(store),
                prefix: object_store::path::Path::default(),
            });
        }
        let (store, prefix) = object_store::parse_url(&url)
            .map_err(|error| NebulaError::Storage(error.to_string()))?;
        Ok(Self {
            store: store.into(),
            s3_signer: None,
            prefix,
        })
    }

    pub async fn ready(&self) -> NebulaResult<()> {
        // Listing the content-addressed root is a cheap cross-backend readiness probe.
        let _ = self
            .store
            .list_with_delimiter(Some(&self.object_path_from_str("blobs")))
            .await
            .map_err(object_store_error)?;
        Ok(())
    }

    fn object_path_from_str(&self, path: &str) -> ObjectPath {
        if self.prefix.as_ref().is_empty() {
            ObjectPath::from(path)
        } else {
            self.prefix.child(path)
        }
    }

    fn object_path(&self, hash: &ContentHash) -> ObjectPath {
        self.object_path_from_str(&hash.object_path())
    }

    pub async fn signed_put_url(
        &self,
        hash: &ContentHash,
        expires_in: Duration,
    ) -> NebulaResult<Option<String>> {
        let Some(s3) = &self.s3_signer else {
            return Ok(None);
        };
        let url = s3
            .signed_url(reqwest::Method::PUT, &self.object_path(hash), expires_in)
            .await
            .map_err(object_store_error)?;
        Ok(Some(url.to_string()))
    }

    pub async fn object_size(&self, hash: &ContentHash) -> NebulaResult<Option<u64>> {
        match self.store.head(&self.object_path(hash)).await {
            Ok(meta) => Ok(Some(meta.size as u64)),
            Err(object_store::Error::NotFound { .. }) => Ok(None),
            Err(error) => Err(object_store_error(error)),
        }
    }

    fn staged_object_path(&self, hash: &ContentHash) -> ObjectPath {
        self.object_path_from_str(&format!("staged/blobs/{}/{}", hash.algorithm, hash.digest))
    }

    pub async fn stage(&self, hash: &ContentHash, bytes: &[u8]) -> NebulaResult<()> {
        verify_bytes_hash(hash, bytes)?;
        self.store
            .put(&self.staged_object_path(hash), bytes.to_vec().into())
            .await
            .map_err(object_store_error)?;
        Ok(())
    }

    pub async fn promote_staged(&self, hash: &ContentHash) -> NebulaResult<()> {
        let staged_path = self.staged_object_path(hash);
        let target_path = self.object_path(hash);
        self.store
            .copy_if_not_exists(&staged_path, &target_path)
            .await
            .or_else(|error| match error {
                object_store::Error::AlreadyExists { .. } => Ok(()),
                _ => Err(object_store_error(error)),
            })?;
        match self.store.delete(&staged_path).await {
            Ok(()) | Err(object_store::Error::NotFound { .. }) => Ok(()),
            Err(error) => Err(object_store_error(error)),
        }
    }

    pub async fn consistency_report(
        &self,
        required_hashes: &[ContentHash],
    ) -> NebulaResult<ObjectStoreConsistencyReport> {
        let mut missing = Vec::new();
        let required_paths = required_hashes
            .iter()
            .map(|hash| self.object_path(hash).to_string())
            .collect::<std::collections::BTreeSet<_>>();
        for hash in required_hashes {
            if !self.exists(hash).await? {
                missing.push(hash.clone());
            }
        }
        let stored_paths = self.list_blob_object_paths().await?;
        let orphaned_paths = stored_paths
            .into_iter()
            .filter(|path| !required_paths.contains(path))
            .collect();
        Ok(ObjectStoreConsistencyReport {
            missing,
            orphaned_paths,
        })
    }

    pub async fn delete_orphaned_objects(
        &self,
        required_hashes: &[ContentHash],
    ) -> NebulaResult<u64> {
        let report = self.consistency_report(required_hashes).await?;
        let mut deleted = 0;
        for path in report.orphaned_paths {
            match self.store.delete(&ObjectPath::from(path.as_str())).await {
                Ok(()) | Err(object_store::Error::NotFound { .. }) => deleted += 1,
                Err(error) => return Err(object_store_error(error)),
            }
        }
        Ok(deleted)
    }

    async fn list_blob_object_paths(&self) -> NebulaResult<Vec<String>> {
        let prefix = self.object_path_from_str("blobs");
        let objects = self
            .store
            .list(Some(&prefix))
            .try_collect::<Vec<_>>()
            .await
            .map_err(object_store_error)?;
        Ok(objects
            .into_iter()
            .map(|meta| meta.location.to_string())
            .collect())
    }
}

#[async_trait]
impl BlobStore for ObjectBlobStore {
    async fn put(&self, hash: &ContentHash, bytes: &[u8]) -> NebulaResult<()> {
        verify_bytes_hash(hash, bytes)?;
        self.store
            .put(&self.object_path(hash), bytes.to_vec().into())
            .await
            .map_err(object_store_error)?;
        Ok(())
    }

    async fn get(&self, hash: &ContentHash) -> NebulaResult<Vec<u8>> {
        let result = self
            .store
            .get(&self.object_path(hash))
            .await
            .map_err(object_store_error)?;
        let bytes = result.bytes().await.map_err(object_store_error)?;
        verify_bytes_hash(hash, &bytes)?;
        Ok(bytes.to_vec())
    }

    async fn exists(&self, hash: &ContentHash) -> NebulaResult<bool> {
        match self.store.head(&self.object_path(hash)).await {
            Ok(_) => Ok(true),
            Err(object_store::Error::NotFound { .. }) => Ok(false),
            Err(error) => Err(object_store_error(error)),
        }
    }

    async fn put_stream(
        &self,
        hash: &ContentHash,
        mut stream: Pin<Box<dyn futures::Stream<Item = NebulaResult<Bytes>> + Send>>,
    ) -> NebulaResult<u64> {
        let upload = self
            .store
            .put_multipart(&self.object_path(hash))
            .await
            .map_err(object_store_error)?;
        let mut writer = WriteMultipart::new(upload);
        let mut hasher = Sha256::new();
        let mut size_bytes = 0u64;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            hasher.update(&chunk);
            size_bytes += chunk.len() as u64;
            writer.put(chunk);
            writer
                .wait_for_capacity(4)
                .await
                .map_err(object_store_error)?;
        }
        let digest = hex::encode(hasher.finalize());
        let actual_hash = ContentHash {
            algorithm: "sha256".to_string(),
            digest,
        };
        if &actual_hash != hash {
            return Err(NebulaError::InvalidOperation(format!(
                "blob checksum mismatch: expected {}:{}, got {}:{}",
                hash.algorithm, hash.digest, actual_hash.algorithm, actual_hash.digest
            )));
        }
        writer.finish().await.map_err(object_store_error)?;
        Ok(size_bytes)
    }

    async fn put_from_path(&self, hash: &ContentHash, path: &Path) -> NebulaResult<u64> {
        let (actual_hash, size_bytes) =
            ContentHash::sha256_reader(fs::File::open(path).map_err(storage_error)?)
                .map_err(storage_error)?;
        if &actual_hash != hash {
            return Err(NebulaError::InvalidOperation(format!(
                "blob checksum mismatch: expected {}:{}, got {}:{}",
                hash.algorithm, hash.digest, actual_hash.algorithm, actual_hash.digest
            )));
        }
        let upload = self
            .store
            .put_multipart(&self.object_path(hash))
            .await
            .map_err(object_store_error)?;
        let mut writer = WriteMultipart::new(upload);
        let mut file = tokio::fs::File::open(path).await.map_err(storage_error)?;
        let mut buffer = vec![0u8; 1024 * 1024];
        loop {
            let read = file.read(&mut buffer).await.map_err(storage_error)?;
            if read == 0 {
                break;
            }
            writer.write(&buffer[..read]);
            writer
                .wait_for_capacity(4)
                .await
                .map_err(object_store_error)?;
        }
        writer.finish().await.map_err(object_store_error)?;
        Ok(size_bytes)
    }

    async fn get_to_path(&self, hash: &ContentHash, path: &Path) -> NebulaResult<u64> {
        let result = self
            .store
            .get(&self.object_path(hash))
            .await
            .map_err(object_store_error)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(storage_error)?;
        }
        let mut file = tokio::fs::File::create(path).await.map_err(storage_error)?;
        let mut stream = result.into_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(object_store_error)?;
            tokio::io::AsyncWriteExt::write_all(&mut file, &chunk)
                .await
                .map_err(storage_error)?;
        }
        file.sync_all().await.map_err(storage_error)?;
        drop(file);
        let (actual_hash, size_bytes) =
            ContentHash::sha256_reader(fs::File::open(path).map_err(storage_error)?)
                .map_err(storage_error)?;
        if &actual_hash != hash {
            return Err(NebulaError::InvalidOperation(format!(
                "blob checksum mismatch: expected {}:{}, got {}:{}",
                hash.algorithm, hash.digest, actual_hash.algorithm, actual_hash.digest
            )));
        }
        Ok(size_bytes)
    }
}

fn verify_bytes_hash(hash: &ContentHash, bytes: &[u8]) -> NebulaResult<()> {
    let actual_hash = ContentHash::sha256(bytes);
    if &actual_hash != hash {
        return Err(NebulaError::InvalidOperation(format!(
            "blob checksum mismatch: expected {}:{}, got {}:{}",
            hash.algorithm, hash.digest, actual_hash.algorithm, actual_hash.digest
        )));
    }
    Ok(())
}

impl PgVectorManifestStore {
    pub async fn connect(database_url: &str) -> NebulaResult<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(database_url)
            .await
            .map_err(sqlx_error)?;
        Ok(Self { pool })
    }

    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn ready(&self) -> NebulaResult<()> {
        sqlx::query("SELECT 1")
            .execute(&self.pool)
            .await
            .map_err(sqlx_error)?;
        Ok(())
    }
}

#[async_trait]
impl VectorIndexStore for PgVectorManifestStore {
    async fn put_manifest(&self, manifest: VectorIndexManifest) -> NebulaResult<()> {
        let json = serde_json::to_value(&manifest).map_err(serde_error)?;
        sqlx::query(
            r#"
            INSERT INTO nebula_registry_objects (object_kind, object_id, repository_id, object_json)
            VALUES ('vector_manifest', $1, $2, $3)
            ON CONFLICT (repository_id, object_kind, object_id)
            DO UPDATE SET
                repository_id = EXCLUDED.repository_id,
                object_json = EXCLUDED.object_json,
                updated_at = NOW()
            "#,
        )
        .bind(manifest.id.as_str())
        .bind(manifest.repository_id.as_str())
        .bind(json)
        .execute(&self.pool)
        .await
        .map_err(sqlx_error)?;
        Ok(())
    }

    async fn put_chunks(
        &self,
        manifest: &VectorIndexManifest,
        chunks: Vec<CodeEmbeddingChunk>,
    ) -> NebulaResult<()> {
        if chunks.iter().any(|chunk| chunk.manifest_id != manifest.id) {
            return Err(NebulaError::InvalidOperation(
                "vector chunk manifest mismatch".to_string(),
            ));
        }
        let mut tx = self.pool.begin().await.map_err(sqlx_error)?;
        for (index, chunk) in chunks.iter().enumerate() {
            let json = serde_json::to_value(chunk).map_err(serde_error)?;
            sqlx::query(
                r#"
                INSERT INTO nebula_registry_objects (object_kind, object_id, repository_id, object_json)
                VALUES ('vector_chunk', $1, $2, $3)
                ON CONFLICT (repository_id, object_kind, object_id)
                DO UPDATE SET
                    repository_id = EXCLUDED.repository_id,
                    object_json = EXCLUDED.object_json,
                    updated_at = NOW()
                "#,
            )
            .bind(format!("{}:{}", manifest.id.as_str(), index))
            .bind(manifest.repository_id.as_str())
            .bind(json)
            .execute(&mut *tx)
            .await
            .map_err(sqlx_error)?;
        }
        tx.commit().await.map_err(sqlx_error)?;
        Ok(())
    }

    async fn get_manifest_for_snapshot(
        &self,
        snapshot_id: &TreeSnapshotId,
    ) -> NebulaResult<Option<VectorIndexManifest>> {
        let rows: Vec<serde_json::Value> = sqlx::query_scalar(
            r#"
            SELECT object_json
            FROM nebula_registry_objects
            WHERE object_kind = 'vector_manifest'
            "#,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(sqlx_error)?;
        for value in rows {
            let manifest: VectorIndexManifest =
                serde_json::from_value(value).map_err(serde_error)?;
            if &manifest.snapshot_id == snapshot_id {
                return Ok(Some(manifest));
            }
        }
        Ok(None)
    }

    async fn get_manifest(
        &self,
        repository_id: &RepositoryId,
        manifest_id: &VectorIndexManifestId,
    ) -> NebulaResult<Option<VectorIndexManifest>> {
        let value: Option<serde_json::Value> = sqlx::query_scalar(
            r#"
            SELECT object_json
            FROM nebula_registry_objects
            WHERE object_kind = 'vector_manifest'
              AND object_id = $1
              AND repository_id = $2
            "#,
        )
        .bind(manifest_id.as_str())
        .bind(repository_id.as_str())
        .fetch_optional(&self.pool)
        .await
        .map_err(sqlx_error)?;
        value
            .map(serde_json::from_value)
            .transpose()
            .map_err(serde_error)
    }

    async fn get_chunks(
        &self,
        repository_id: &RepositoryId,
        manifest_id: &VectorIndexManifestId,
    ) -> NebulaResult<Vec<CodeEmbeddingChunk>> {
        let rows: Vec<serde_json::Value> = sqlx::query_scalar(
            r#"
            SELECT object_json
            FROM nebula_registry_objects
            WHERE object_kind = 'vector_chunk'
              AND object_id LIKE $1
              AND repository_id = $2
            ORDER BY object_id ASC
            "#,
        )
        .bind(format!("{}:%", manifest_id.as_str()))
        .bind(repository_id.as_str())
        .fetch_all(&self.pool)
        .await
        .map_err(sqlx_error)?;
        rows.into_iter()
            .map(serde_json::from_value)
            .collect::<Result<Vec<_>, _>>()
            .map_err(serde_error)
    }

    async fn search_chunks(
        &self,
        repository_id: &RepositoryId,
        manifest_id: &VectorIndexManifestId,
        query: &str,
        top_k: usize,
    ) -> NebulaResult<Vec<CodeEmbeddingChunk>> {
        let query = query.to_lowercase();
        Ok(self
            .get_chunks(repository_id, manifest_id)
            .await?
            .into_iter()
            .filter(|chunk| query.is_empty() || chunk.path.to_lowercase().contains(&query))
            .take(top_k)
            .collect())
    }
}

fn storage_error(error: std::io::Error) -> NebulaError {
    NebulaError::Storage(error.to_string())
}

fn sqlx_error(error: sqlx::Error) -> NebulaError {
    NebulaError::Storage(error.to_string())
}

fn object_store_error(error: object_store::Error) -> NebulaError {
    match error {
        object_store::Error::NotFound { path, .. } => NebulaError::NotFound(path),
        other => NebulaError::Storage(other.to_string()),
    }
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;
    use nebula_core::VectorIndexManifestId;

    #[tokio::test]
    async fn file_vector_store_persists_and_searches_chunks() {
        let root = std::env::temp_dir().join(format!(
            "nebula-vector-store-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let store = FileVectorIndexStore::new(&root);
        let repository_id = RepositoryId::generated();
        let manifest = VectorIndexManifest {
            id: VectorIndexManifestId::generated(),
            repository_id: repository_id.clone(),
            snapshot_id: TreeSnapshotId::generated(),
            projection_id: None,
            index_version: "test".to_string(),
            chunk_count: 1,
            embedding_model: "test".to_string(),
            promoted_at_unix_ms: Some(1),
            tombstoned_at_unix_ms: None,
        };
        let chunk = CodeEmbeddingChunk {
            manifest_id: manifest.id.clone(),
            path: "src/search.rs".to_string(),
            start_line: Some(1),
            end_line: Some(3),
            content_hash: ContentHash::sha256(b"search"),
        };

        store.put_manifest(manifest.clone()).await.unwrap();
        store
            .put_chunks(&manifest, vec![chunk.clone()])
            .await
            .unwrap();

        assert_eq!(
            store
                .get_manifest(&repository_id, &manifest.id)
                .await
                .unwrap()
                .unwrap()
                .id,
            manifest.id
        );
        assert_eq!(
            store
                .search_chunks(&repository_id, &manifest.id, "search", 10)
                .await
                .unwrap(),
            vec![chunk]
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn ops_plans_are_explicit_and_safe_by_default() {
        let retention = default_retention_plan();
        assert!(retention.authorization_audit_retention_days >= 30);
        let restore = production_restore_plan("metadata.json", "blobs/", None);
        assert!(restore.verify_checksums);
        let migration = production_migration_plan(MetadataBackend::Postgres {
            database_url: "$DATABASE_URL".to_string(),
        });
        assert!(
            migration
                .required_migrations
                .contains(&"0001_registry_objects".to_string())
        );
    }
}

fn serde_error(error: serde_json::Error) -> NebulaError {
    NebulaError::Storage(error.to_string())
}
