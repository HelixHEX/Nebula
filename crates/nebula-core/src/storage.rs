use crate::ids::*;
use crate::model::*;
use async_trait::async_trait;
use bytes::Bytes;
use futures::Stream;
use std::pin::Pin;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum NebulaError {
    #[error("not found: {0}")]
    NotFound(String),
    #[error("policy blocked: {0}")]
    PolicyBlocked(String),
    #[error("storage error: {0}")]
    Storage(String),
    #[error("invalid operation: {0}")]
    InvalidOperation(String),
}

pub type NebulaResult<T> = Result<T, NebulaError>;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct RegistryMutation {
    pub repository_id: Option<RepositoryId>,
    pub kind: String,
    pub id: String,
    pub value: serde_json::Value,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct RefCompareAndSwap {
    pub repository_id: RepositoryId,
    pub name: String,
    pub expected_target: Option<serde_json::Value>,
    pub next_ref: serde_json::Value,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct RegistryTransaction {
    pub id: String,
    pub repository_id: Option<RepositoryId>,
    pub idempotency_key: Option<String>,
    pub mutations: Vec<RegistryMutation>,
    pub ref_updates: Vec<RefCompareAndSwap>,
    pub audit: RegistryMutationAudit,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct RegistryMutationAudit {
    pub actor: Option<Actor>,
    pub action: String,
    pub reason: Option<String>,
    pub created_at_unix_ms: u64,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct RegistryTransactionResult {
    pub transaction_id: String,
    pub committed: bool,
    pub mutation_count: usize,
}

#[async_trait]
pub trait BlobStore: Send + Sync {
    async fn put(&self, hash: &ContentHash, bytes: &[u8]) -> NebulaResult<()>;
    async fn get(&self, hash: &ContentHash) -> NebulaResult<Vec<u8>>;
    async fn exists(&self, hash: &ContentHash) -> NebulaResult<bool>;
    async fn put_stream(
        &self,
        hash: &ContentHash,
        stream: Pin<Box<dyn Stream<Item = NebulaResult<Bytes>> + Send>>,
    ) -> NebulaResult<u64>;
    async fn put_from_path(&self, hash: &ContentHash, path: &std::path::Path) -> NebulaResult<u64>;
    async fn get_to_path(&self, hash: &ContentHash, path: &std::path::Path) -> NebulaResult<u64>;
}

#[async_trait]
pub trait MetadataStore: Send + Sync {
    async fn put_snapshot(&self, snapshot: TreeSnapshot) -> NebulaResult<()>;
    async fn get_snapshot(&self, id: &TreeSnapshotId) -> NebulaResult<TreeSnapshot>;
    async fn put_ref(&self, reference: Ref) -> NebulaResult<()>;
    async fn get_ref_by_name(&self, repository_id: &RepositoryId, name: &str) -> NebulaResult<Ref>;
    async fn put_changeset(&self, changeset: ChangeSet) -> NebulaResult<()>;
    async fn get_changeset(&self, id: &ChangeSetId) -> NebulaResult<ChangeSet>;
    async fn put_proposal(&self, proposal: Proposal) -> NebulaResult<()>;
    async fn get_proposal(&self, id: &ProposalId) -> NebulaResult<Proposal>;
}

#[async_trait]
pub trait VectorIndexStore: Send + Sync {
    async fn put_manifest(&self, manifest: VectorIndexManifest) -> NebulaResult<()>;
    async fn put_chunks(
        &self,
        manifest: &VectorIndexManifest,
        chunks: Vec<CodeEmbeddingChunk>,
    ) -> NebulaResult<()>;
    async fn get_manifest_for_snapshot(
        &self,
        snapshot_id: &TreeSnapshotId,
    ) -> NebulaResult<Option<VectorIndexManifest>>;
    async fn get_manifest(
        &self,
        repository_id: &RepositoryId,
        manifest_id: &VectorIndexManifestId,
    ) -> NebulaResult<Option<VectorIndexManifest>>;
    async fn get_chunks(
        &self,
        repository_id: &RepositoryId,
        manifest_id: &VectorIndexManifestId,
    ) -> NebulaResult<Vec<CodeEmbeddingChunk>>;
    async fn search_chunks(
        &self,
        repository_id: &RepositoryId,
        manifest_id: &VectorIndexManifestId,
        query: &str,
        top_k: usize,
    ) -> NebulaResult<Vec<CodeEmbeddingChunk>>;
}

#[async_trait]
pub trait RegistryStore: Send + Sync {
    async fn put_repository_record(
        &self,
        repository_id: &RepositoryId,
        value: serde_json::Value,
    ) -> NebulaResult<()>;
    async fn get_repository_record(
        &self,
        repository_id: &RepositoryId,
    ) -> NebulaResult<serde_json::Value>;
    async fn put_resource(
        &self,
        repository_id: Option<&RepositoryId>,
        kind: &str,
        id: &str,
        value: serde_json::Value,
    ) -> NebulaResult<()>;
    async fn get_resource(&self, kind: &str, id: &str) -> NebulaResult<serde_json::Value>;
    async fn get_resource_scoped(
        &self,
        repository_id: Option<&RepositoryId>,
        kind: &str,
        id: &str,
    ) -> NebulaResult<serde_json::Value>;
    async fn list_resources(&self, kind: &str) -> NebulaResult<Vec<serde_json::Value>>;
    async fn list_resources_scoped(
        &self,
        repository_id: Option<&RepositoryId>,
        kind: &str,
    ) -> NebulaResult<Vec<serde_json::Value>>;
    async fn delete_resource(
        &self,
        repository_id: Option<&RepositoryId>,
        kind: &str,
        id: &str,
    ) -> NebulaResult<()>;
    async fn put_resource_idempotent(
        &self,
        repository_id: Option<&RepositoryId>,
        kind: &str,
        id: &str,
        idempotency_key: &str,
        value: serde_json::Value,
    ) -> NebulaResult<serde_json::Value>;
    async fn compare_and_swap_ref(
        &self,
        repository_id: &RepositoryId,
        name: &str,
        expected_target: Option<serde_json::Value>,
        next_ref: serde_json::Value,
    ) -> NebulaResult<bool>;
    async fn commit_transaction(
        &self,
        transaction: RegistryTransaction,
    ) -> NebulaResult<RegistryTransactionResult>;
}

#[async_trait]
pub trait RegistryService: Send + Sync {
    async fn resolve_ref(&self, repository_id: &RepositoryId, name: &str) -> NebulaResult<Ref>;
    async fn create_workspace(
        &self,
        repository_id: RepositoryId,
        base_snapshot_id: TreeSnapshotId,
        owner: WorkspaceOwner,
        environment_id: Option<EnvironmentId>,
    ) -> NebulaResult<AgentWorkspace>;
    async fn create_proposal(
        &self,
        title: String,
        target_ref_id: RefId,
        changeset_ids: Vec<ChangeSetId>,
    ) -> NebulaResult<Proposal>;
}
