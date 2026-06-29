use crate::ids::*;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ModelValidationError {
    #[error("path is empty")]
    EmptyPath,
    #[error("absolute paths are not allowed: {0}")]
    AbsolutePath(String),
    #[error("path traversal is not allowed: {0}")]
    PathTraversal(String),
    #[error("duplicate tree entry path: {0}")]
    DuplicatePath(String),
    #[error("file entry requires content hash: {0}")]
    MissingFileHash(String),
    #[error("tree entry cannot be inserted below a file path: {0}")]
    FilePathConflict(String),
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub enum BlobVisibility {
    Public,
    PolicyScoped(PolicyId),
    Encrypted { key_envelope_id: String },
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct ContentBlob {
    pub id: BlobId,
    pub hash: ContentHash,
    pub size_bytes: u64,
    pub media_type: Option<String>,
    pub visibility: BlobVisibility,
}

pub const DEFAULT_BLOB_CHUNK_SIZE: usize = 4 * 1024 * 1024;
pub const MAX_IN_MEMORY_BLOB_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub enum TelemetrySeverity {
    Debug,
    Info,
    Warning,
    Error,
    Critical,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub enum TelemetrySource {
    Registry,
    Sync,
    BlobStore,
    VectorIndex,
    Auth,
    OpsCli,
    BackupRestore,
    AstracollabAdapter,
    LucityAdapter,
}

#[derive(Clone, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct NebulaTelemetryContext {
    pub organization_id: Option<String>,
    pub repository_id: Option<RepositoryId>,
    pub sync_session_id: Option<SyncSessionId>,
    pub deploy_intent_id: Option<DeployIntentId>,
    pub trace_id: Option<String>,
    pub request_id: Option<String>,
}

#[derive(Clone, Debug, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct NebulaTelemetryEvent {
    pub event_id: String,
    pub event_type: String,
    pub source: TelemetrySource,
    pub severity: TelemetrySeverity,
    pub message: String,
    pub context: NebulaTelemetryContext,
    pub created_at_unix_ms: u64,
    pub attributes: BTreeMap<String, serde_json::Value>,
}

#[derive(Clone, Debug, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct NebulaOpsReportEnvelope {
    pub report_id: String,
    pub report_type: String,
    pub source: TelemetrySource,
    pub severity: TelemetrySeverity,
    pub context: NebulaTelemetryContext,
    pub created_at_unix_ms: u64,
    pub dry_run: bool,
    pub outcome: String,
    pub report: serde_json::Value,
    pub follow_up_actions: Vec<String>,
}

impl ContentBlob {
    pub fn from_bytes(
        bytes: &[u8],
        media_type: Option<String>,
        visibility: BlobVisibility,
    ) -> Self {
        let hash = ContentHash::sha256(bytes);
        Self {
            id: BlobId::from_hash(&hash),
            hash,
            size_bytes: bytes.len() as u64,
            media_type,
            visibility,
        }
    }
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct BlobChunk {
    pub id: BlobChunkId,
    pub hash: ContentHash,
    pub offset: u64,
    pub size_bytes: u64,
}

impl BlobChunk {
    pub fn from_bytes(offset: u64, bytes: &[u8]) -> Self {
        let hash = ContentHash::sha256(bytes);
        Self {
            id: BlobChunkId::from_hash(&hash),
            hash,
            offset,
            size_bytes: bytes.len() as u64,
        }
    }
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub enum StagedBlobState {
    Uploaded,
    Promoted,
    Corrupt,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct StagedBlobUpload {
    pub repository_id: RepositoryId,
    pub session_id: SyncSessionId,
    pub blob: ContentBlob,
    pub received_bytes: u64,
    pub state: StagedBlobState,
    pub created_at_unix_ms: u64,
    pub updated_at_unix_ms: u64,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct BlobStreamDescriptor {
    pub blob: ContentBlob,
    pub chunk_size: u64,
    pub chunks: Vec<BlobChunk>,
}

impl BlobStreamDescriptor {
    pub fn single_blob(blob: ContentBlob) -> Self {
        let chunk = BlobChunk {
            id: BlobChunkId::from_hash(&blob.hash),
            hash: blob.hash.clone(),
            offset: 0,
            size_bytes: blob.size_bytes,
        };
        Self {
            blob,
            chunk_size: DEFAULT_BLOB_CHUNK_SIZE as u64,
            chunks: vec![chunk],
        }
    }
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct ChunkedBlob {
    pub blob: ContentBlob,
    pub chunks: Vec<BlobChunk>,
}

impl ChunkedBlob {
    pub fn from_bytes(
        bytes: &[u8],
        media_type: Option<String>,
        visibility: BlobVisibility,
        chunk_size: usize,
    ) -> Self {
        let blob = ContentBlob::from_bytes(bytes, media_type, visibility);
        let chunk_size = chunk_size.max(1);
        let chunks = bytes
            .chunks(chunk_size)
            .enumerate()
            .map(|(index, chunk)| BlobChunk::from_bytes((index * chunk_size) as u64, chunk))
            .collect();
        Self { blob, chunks }
    }
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub enum TreeEntryKind {
    File,
    Directory,
    Symlink,
    Executable,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct TreeEntry {
    pub path: String,
    pub kind: TreeEntryKind,
    pub blob_id: Option<BlobId>,
    pub hash: Option<ContentHash>,
    pub size_bytes: Option<u64>,
    pub policy_id: Option<PolicyId>,
}

impl TreeEntry {
    pub fn file(
        path: impl Into<String>,
        blob: &ContentBlob,
        policy_id: Option<PolicyId>,
    ) -> Result<Self, ModelValidationError> {
        let path = normalize_repo_path(&path.into())?;
        Ok(Self {
            path,
            kind: TreeEntryKind::File,
            blob_id: Some(blob.id.clone()),
            hash: Some(blob.hash.clone()),
            size_bytes: Some(blob.size_bytes),
            policy_id,
        })
    }

    pub fn directory(path: impl Into<String>) -> Result<Self, ModelValidationError> {
        let path = normalize_repo_path(&path.into())?;
        Ok(Self {
            path,
            kind: TreeEntryKind::Directory,
            blob_id: None,
            hash: None,
            size_bytes: None,
            policy_id: None,
        })
    }
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct TreeSnapshot {
    pub id: TreeSnapshotId,
    pub repository_id: RepositoryId,
    pub root_tree_id: TreeNodeId,
    pub root_hash: ContentHash,
    pub parent_snapshot_ids: Vec<TreeSnapshotId>,
    pub entries: Vec<TreeEntry>,
    pub metadata: BTreeMap<String, String>,
}

impl TreeSnapshot {
    pub fn canonical(
        repository_id: RepositoryId,
        parent_snapshot_ids: Vec<TreeSnapshotId>,
        entries: Vec<TreeEntry>,
        metadata: BTreeMap<String, String>,
    ) -> Result<Self, ModelValidationError> {
        let entries = canonicalize_entries(entries)?;
        let root_node = TreeNode::from_entries("", &entries)?;
        let root_hash = root_node.hash.clone();
        Ok(Self {
            id: TreeSnapshotId::from_root_hash(&root_hash),
            repository_id,
            root_tree_id: root_node.id,
            root_hash,
            parent_snapshot_ids,
            entries,
            metadata,
        })
    }
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub enum TreeNodeEntryTarget {
    Tree(TreeNodeId),
    Blob(BlobId),
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct TreeNodeEntry {
    pub name: String,
    pub kind: TreeEntryKind,
    pub target: TreeNodeEntryTarget,
    pub hash: ContentHash,
    pub size_bytes: Option<u64>,
    pub policy_id: Option<PolicyId>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct TreeNode {
    pub id: TreeNodeId,
    pub path: String,
    pub hash: ContentHash,
    pub entries: Vec<TreeNodeEntry>,
}

impl TreeNode {
    pub fn new(path: impl Into<String>, entries: Vec<TreeNodeEntry>) -> Self {
        let path = path.into();
        let hash = compute_tree_node_hash(&entries);
        Self {
            id: TreeNodeId::from_hash(&hash),
            path,
            hash,
            entries,
        }
    }

    pub fn from_entries(path: &str, entries: &[TreeEntry]) -> Result<Self, ModelValidationError> {
        let nodes = build_tree_nodes(entries)?;
        let normalized = if path.is_empty() {
            "".to_string()
        } else {
            normalize_repo_path(path)?
        };
        nodes
            .into_iter()
            .find(|node| node.path == normalized)
            .ok_or(ModelValidationError::EmptyPath)
    }
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub enum RefTarget {
    Snapshot(TreeSnapshotId),
    ChangeSet(ChangeSetId),
    Proposal(ProposalId),
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct Ref {
    pub id: RefId,
    pub repository_id: RepositoryId,
    pub name: String,
    pub target: RefTarget,
    pub policy_id: Option<PolicyId>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub enum WorkspaceOwner {
    User(String),
    Team(String),
    Agent(String),
    Integration(String),
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct AgentWorkspace {
    pub id: WorkspaceId,
    pub repository_id: RepositoryId,
    pub base_snapshot_id: TreeSnapshotId,
    pub owner: WorkspaceOwner,
    pub environment_id: Option<EnvironmentId>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub enum ChangeOperationKind {
    Add,
    Modify,
    Delete,
    Rename { from_path: String },
    ModeChange,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct ChangeOperation {
    pub path: String,
    pub kind: ChangeOperationKind,
    pub before_blob_id: Option<BlobId>,
    pub after_blob_id: Option<BlobId>,
    pub policy_id: Option<PolicyId>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct ChangeSet {
    pub id: ChangeSetId,
    pub repository_id: RepositoryId,
    pub workspace_id: WorkspaceId,
    pub base_snapshot_id: TreeSnapshotId,
    pub next_snapshot_id: TreeSnapshotId,
    pub author: Actor,
    pub summary: String,
    pub operations: Vec<ChangeOperation>,
    #[serde(default)]
    pub changed_paths: Vec<String>,
    #[serde(default)]
    pub changed_symbols: Vec<String>,
    #[serde(default)]
    pub changed_packages: Vec<String>,
    #[serde(default)]
    pub affected_targets: Vec<String>,
    #[serde(default)]
    pub affected_tests: Vec<String>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub enum ReviewState {
    Open,
    Approved,
    Blocked,
    Merged,
    Closed,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct Proposal {
    pub id: ProposalId,
    pub repository_id: RepositoryId,
    pub title: String,
    pub target_ref_id: RefId,
    pub changeset_ids: Vec<ChangeSetId>,
    pub state: ReviewState,
    pub policy_checks: Vec<PolicyCheck>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub enum MergeStrategy {
    DeterministicThreeWay,
    FastForwardOnly,
    AgentAssisted,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct MergeIntent {
    pub id: MergeIntentId,
    pub repository_id: RepositoryId,
    pub proposal_id: ProposalId,
    pub target_ref_id: RefId,
    pub strategy: MergeStrategy,
    pub requested_by: Actor,
    pub release_gate_id: Option<ReleaseGateId>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub enum MergeConflictKind {
    PathConflict,
    DeleteEdit,
    Binary,
    Visibility,
    DivergedRef,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct MergeConflict {
    pub path: String,
    pub kind: MergeConflictKind,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub enum MergeState {
    Clean,
    Blocked,
    Merged,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct MergeResult {
    pub intent_id: MergeIntentId,
    pub state: MergeState,
    pub output_snapshot_id: Option<TreeSnapshotId>,
    pub conflicts: Vec<MergeConflict>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub enum ReleaseGateKind {
    Immediate,
    DelayedUntil { unix_ms: u64 },
    Embargoed,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct ReleaseGate {
    pub id: ReleaseGateId,
    pub repository_id: RepositoryId,
    pub environment_id: Option<EnvironmentId>,
    pub kind: ReleaseGateKind,
    pub required_actor: Option<Actor>,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub enum EnvironmentKind {
    Development,
    Staging,
    Production,
    Custom(String),
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct Environment {
    pub id: EnvironmentId,
    pub repository_id: RepositoryId,
    pub name: String,
    pub kind: EnvironmentKind,
}

#[derive(Clone, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
pub enum Actor {
    User(String),
    Team(String),
    Agent(String),
    Integration(String),
    Public,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct IntegrationActor {
    pub actor: Actor,
    pub provider: String,
    pub display_name: String,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub enum AuthTokenKind {
    User,
    Agent,
    Integration,
    DeploymentGrant,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct AuthToken {
    pub id: AuthTokenId,
    pub repository_id: Option<RepositoryId>,
    #[serde(default)]
    pub org_id: Option<String>,
    pub actor: Actor,
    pub kind: AuthTokenKind,
    pub name: String,
    pub token_hash: String,
    pub scopes: Vec<PolicyAction>,
    pub expires_at_unix_ms: Option<u64>,
    pub revoked_at_unix_ms: Option<u64>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub enum ReviewCommentState {
    Open,
    Resolved,
    Hidden,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct ProposalComment {
    pub id: ReviewCommentId,
    pub repository_id: RepositoryId,
    pub proposal_id: ProposalId,
    pub author: Actor,
    pub body_markdown: String,
    pub path: Option<String>,
    pub line: Option<u32>,
    pub state: ReviewCommentState,
    pub created_at_unix_ms: u64,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub enum StatusCheckState {
    Queued,
    Running,
    Passed,
    Failed,
    Skipped,
    Cancelled,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct ProposalStatusCheck {
    pub id: StatusCheckId,
    pub repository_id: RepositoryId,
    pub proposal_id: ProposalId,
    pub name: String,
    pub actor: Actor,
    pub state: StatusCheckState,
    pub summary: Option<String>,
    pub target_url: Option<String>,
    pub started_at_unix_ms: Option<u64>,
    pub completed_at_unix_ms: Option<u64>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub enum WebhookEventKind {
    RefUpdated,
    ProposalOpened,
    ProposalMerged,
    ProjectionReady,
    VectorIndexReady,
    ReleaseGateOpened,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct WebhookEndpoint {
    pub id: WebhookEndpointId,
    pub repository_id: Option<RepositoryId>,
    pub url: String,
    pub description: Option<String>,
    pub subscribed_events: Vec<WebhookEventKind>,
    pub secret_ref: Option<String>,
    pub active: bool,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub enum WebhookDeliveryState {
    Pending,
    Delivered,
    Failed,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct WebhookEvent {
    pub id: WebhookEventId,
    pub endpoint_id: WebhookEndpointId,
    pub repository_id: RepositoryId,
    pub kind: WebhookEventKind,
    pub state: WebhookDeliveryState,
    pub payload_ref: Option<String>,
    pub attempts: u32,
    pub next_attempt_unix_ms: Option<u64>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub enum SyncSessionState {
    Open,
    Uploading,
    Validated,
    Completed,
    Failed,
    Aborted,
    Expired,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct SyncSession {
    pub id: SyncSessionId,
    pub repository_id: RepositoryId,
    pub actor: Actor,
    pub base_snapshot_id: Option<TreeSnapshotId>,
    pub target_ref: Option<String>,
    pub state: SyncSessionState,
    pub lease_expires_at_unix_ms: u64,
    pub uploaded_blob_count: u64,
    pub downloaded_blob_count: u64,
    pub operation_id: Option<OperationId>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct BlobChunkDescriptor {
    #[serde(default)]
    pub blob_hash: Option<ContentHash>,
    pub hash: ContentHash,
    pub offset: u64,
    pub size_bytes: u64,
    pub digest: String,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct ChunkTransferManifest {
    pub repository_id: RepositoryId,
    pub session_id: SyncSessionId,
    pub chunks: Vec<BlobChunkDescriptor>,
    pub total_bytes: u64,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub enum ProjectionTarget {
    GitHub,
    GitRemote(String),
    Vercel,
    Ci(String),
    Local,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct Projection {
    pub id: ProjectionId,
    pub repository_id: RepositoryId,
    pub snapshot_id: TreeSnapshotId,
    pub environment_id: EnvironmentId,
    pub target: ProjectionTarget,
    pub actor: Actor,
    pub policy_checks: Vec<PolicyCheck>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct ProjectionManifest {
    pub projection_id: ProjectionId,
    pub snapshot_id: TreeSnapshotId,
    pub included_tree_roots: Vec<TreeNodeId>,
    pub included_paths: Vec<String>,
    pub redacted_paths: Vec<String>,
    pub templated_paths: Vec<String>,
    pub omitted_paths: Vec<String>,
    pub blocked_paths: Vec<String>,
}

impl ProjectionManifest {
    pub fn empty(projection_id: ProjectionId, snapshot_id: TreeSnapshotId) -> Self {
        Self {
            projection_id,
            snapshot_id,
            included_tree_roots: Vec::new(),
            included_paths: Vec::new(),
            redacted_paths: Vec::new(),
            templated_paths: Vec::new(),
            omitted_paths: Vec::new(),
            blocked_paths: Vec::new(),
        }
    }

    pub fn has_blockers(&self) -> bool {
        !self.blocked_paths.is_empty()
    }
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct DeploymentGrant {
    pub id: DeploymentGrantId,
    pub projection_id: ProjectionId,
    pub actor: Actor,
    pub expires_at_unix_ms: u64,
    pub allowed_actions: Vec<PolicyAction>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub enum DeployIntentState {
    Queued,
    SentToAstracollab,
    Running,
    Succeeded,
    Failed,
    Cancelled,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct DeployArtifactRef {
    pub kind: String,
    pub uri: String,
    pub digest: Option<String>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct DeployTriggerSource {
    pub kind: String,
    pub installation_id: Option<String>,
    pub event_id: Option<String>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct DeployTarget {
    pub provider_key: String,
    pub service_id: String,
    pub environment_name: Option<String>,
    pub context_path: Option<String>,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
pub struct RepositoryDeployConfig {
    pub repository_id: RepositoryId,
    pub provider_key: String,
    pub deploy_url: String,
    pub signing_secret: String,
    pub service_id: String,
    #[serde(default)]
    pub environment_name: Option<String>,
    #[serde(default)]
    pub context_path: Option<String>,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
pub struct RepositoryDeployConfigView {
    pub provider_key: String,
    pub deploy_url: String,
    pub service_id: String,
    #[serde(default)]
    pub environment_name: Option<String>,
    #[serde(default)]
    pub context_path: Option<String>,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
pub struct SetRepositoryDeployConfigRequest {
    pub provider_key: String,
    pub deploy_url: String,
    pub signing_secret: String,
    pub service_id: String,
    #[serde(default)]
    pub environment_name: Option<String>,
    #[serde(default)]
    pub context_path: Option<String>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct DeployPolicyEvidence {
    pub required_actions: Vec<PolicyAction>,
    pub allowed_actions: Vec<PolicyAction>,
    pub blocked_count: u32,
    pub embargo_count: u32,
    pub manifest_digest: String,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub enum ReleaseGateDecision {
    Allow,
    Block,
    Embargo { until_unix_ms: u64 },
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct DeployReleaseGateEvidence {
    pub gate_id: Option<ReleaseGateId>,
    pub kind: Option<ReleaseGateKind>,
    pub decision: ReleaseGateDecision,
    pub reason: String,
    pub effective_at_unix_ms: Option<u64>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct AstracollabDeployHandoff {
    pub request_id: String,
    pub endpoint: Option<String>,
    pub signature: String,
    pub sent_at_unix_ms: u64,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct DeployIntent {
    pub schema_version: u32,
    pub id: DeployIntentId,
    pub repository_id: RepositoryId,
    pub projection_id: ProjectionId,
    pub snapshot_id: TreeSnapshotId,
    pub environment_id: EnvironmentId,
    pub requested_provider_key: String,
    pub requested_by: Actor,
    pub target: Option<DeployTarget>,
    pub policy_evidence: Option<DeployPolicyEvidence>,
    pub release_gate_evidence: Option<DeployReleaseGateEvidence>,
    pub trigger_source: Option<DeployTriggerSource>,
    pub state: DeployIntentState,
    pub astracollab_request_id: Option<String>,
    pub handoff: Option<AstracollabDeployHandoff>,
    pub artifacts: Vec<DeployArtifactRef>,
    pub log_uri: Option<String>,
    pub error_message: Option<String>,
    pub attempts: u32,
    pub created_at_unix_ms: u64,
    pub updated_at_unix_ms: u64,
    pub completed_at_unix_ms: Option<u64>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct SecretFileRef {
    pub id: SecretFileRefId,
    pub repository_id: RepositoryId,
    pub name: String,
    pub environment_id: Option<EnvironmentId>,
    pub blob_id: Option<BlobId>,
    pub key_envelope_id: Option<String>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct GitExport {
    pub id: GitExportId,
    pub proposal_id: ProposalId,
    pub projection_id: ProjectionId,
    pub remote_name: String,
    pub branch_name: String,
    pub commit_sha: Option<String>,
    pub pull_request_url: Option<String>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct GitMigrationRecord {
    pub id: GitMigrationRecordId,
    pub repository_id: RepositoryId,
    pub git_commit_sha: String,
    pub git_tree_sha: String,
    pub parent_commit_shas: Vec<String>,
    pub snapshot_id: TreeSnapshotId,
    pub author_name: String,
    pub author_email: String,
    pub committer_name: String,
    pub committer_email: String,
    pub message: String,
    pub tag_names: Vec<String>,
    pub submodule_paths: Vec<String>,
    pub lfs_pointer_paths: Vec<String>,
    pub signature_status: Option<String>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct VectorIndexManifest {
    pub id: VectorIndexManifestId,
    pub repository_id: RepositoryId,
    pub snapshot_id: TreeSnapshotId,
    #[serde(default)]
    pub projection_id: Option<ProjectionId>,
    pub index_version: String,
    pub chunk_count: u64,
    pub embedding_model: String,
    #[serde(default)]
    pub promoted_at_unix_ms: Option<u64>,
    #[serde(default)]
    pub tombstoned_at_unix_ms: Option<u64>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub enum VectorIndexJobState {
    Queued,
    Running,
    Ready,
    Failed,
    Cancelled,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct VectorIndexJob {
    pub id: VectorIndexJobId,
    pub repository_id: RepositoryId,
    pub snapshot_id: TreeSnapshotId,
    pub projection_id: Option<ProjectionId>,
    pub requested_by: Actor,
    pub worker_kind: String,
    pub state: VectorIndexJobState,
    pub manifest_id: Option<VectorIndexManifestId>,
    pub error_message: Option<String>,
    pub queued_at_unix_ms: u64,
    pub started_at_unix_ms: Option<u64>,
    pub completed_at_unix_ms: Option<u64>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct CodeEmbeddingChunk {
    pub manifest_id: VectorIndexManifestId,
    pub path: String,
    pub start_line: Option<u32>,
    pub end_line: Option<u32>,
    pub content_hash: ContentHash,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct PolicyCheck {
    pub actor: Actor,
    pub environment_id: Option<EnvironmentId>,
    pub action: PolicyAction,
    pub object: PolicyObject,
    pub decision: PolicyDecision,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub enum PolicyAction {
    ReadBlob,
    ReadPath,
    PullImage,
    PushImage,
    WriteChangeSet,
    ApproveChangeSet,
    MergeChangeSet,
    ExportGit,
    ReadSecret,
    InjectSecret,
    ReadBuildSource,
    CreateProjection,
    Deploy,
    ManageAuth,
    ManageWebhooks,
    SyncObjects,
    ReviewProposal,
    RunStatusCheck,
    IndexCode,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub enum PolicyObject {
    Blob(BlobId),
    Path(String),
    ChangeSet(ChangeSetId),
    Proposal(ProposalId),
    Projection(ProjectionId),
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub enum PolicyDecision {
    Allow,
    Redact,
    Template,
    Omit,
    Block,
    Embargo { until_unix_ms: u64 },
}

pub fn normalize_repo_path(raw: &str) -> Result<String, ModelValidationError> {
    let normalized = raw.trim().replace('\\', "/");
    if normalized.is_empty() {
        return Err(ModelValidationError::EmptyPath);
    }
    if normalized.starts_with('/') {
        return Err(ModelValidationError::AbsolutePath(raw.to_string()));
    }

    let mut parts = Vec::new();
    for part in normalized.split('/') {
        match part {
            "" | "." => continue,
            ".." => return Err(ModelValidationError::PathTraversal(raw.to_string())),
            _ => parts.push(part),
        }
    }

    if parts.is_empty() {
        return Err(ModelValidationError::EmptyPath);
    }

    Ok(parts.join("/"))
}

pub fn canonicalize_entries(
    entries: Vec<TreeEntry>,
) -> Result<Vec<TreeEntry>, ModelValidationError> {
    let mut seen = BTreeSet::new();
    let mut normalized = Vec::with_capacity(entries.len());

    for mut entry in entries {
        entry.path = normalize_repo_path(&entry.path)?;
        if !seen.insert(entry.path.clone()) {
            return Err(ModelValidationError::DuplicatePath(entry.path));
        }
        let is_content_entry = matches!(
            entry.kind,
            TreeEntryKind::File | TreeEntryKind::Executable | TreeEntryKind::Symlink
        );
        if is_content_entry {
            if entry.hash.is_none() || entry.blob_id.is_none() || entry.size_bytes.is_none() {
                return Err(ModelValidationError::MissingFileHash(entry.path));
            }
        } else if entry.hash.is_some() || entry.blob_id.is_some() || entry.size_bytes.is_some() {
            return Err(ModelValidationError::FilePathConflict(entry.path));
        }
        normalized.push(entry);
    }

    normalized.sort_by(|a, b| a.path.cmp(&b.path));
    let file_paths = normalized
        .iter()
        .filter(|entry| !matches!(entry.kind, TreeEntryKind::Directory))
        .map(|entry| entry.path.as_str())
        .collect::<Vec<_>>();
    for entry in &normalized {
        for file_path in &file_paths {
            if entry.path.starts_with(&format!("{file_path}/")) {
                return Err(ModelValidationError::FilePathConflict(entry.path.clone()));
            }
        }
    }
    Ok(normalized)
}

pub fn compute_tree_root_hash(entries: &[TreeEntry]) -> ContentHash {
    let canonical = canonicalize_entries(entries.to_vec()).unwrap_or_default();
    TreeNode::from_entries("", &canonical)
        .map(|node| node.hash)
        .unwrap_or_else(|_| ContentHash::sha256(b""))
}

pub fn build_tree_nodes(entries: &[TreeEntry]) -> Result<Vec<TreeNode>, ModelValidationError> {
    let entries = canonicalize_entries(entries.to_vec())?;
    let mut nodes = Vec::new();
    build_tree_node_recursive("", &entries, &mut nodes)?;
    nodes.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(nodes)
}

fn build_tree_node_recursive(
    path: &str,
    entries: &[TreeEntry],
    nodes: &mut Vec<TreeNode>,
) -> Result<TreeNode, ModelValidationError> {
    let mut direct_entries = Vec::new();
    let mut child_groups: BTreeMap<String, Vec<TreeEntry>> = BTreeMap::new();

    for entry in entries {
        let relative = if path.is_empty() {
            entry.path.as_str()
        } else if let Some(suffix) = entry.path.strip_prefix(&format!("{path}/")) {
            suffix
        } else {
            continue;
        };

        let Some((first, rest)) = relative.split_once('/') else {
            direct_entries.push(entry.clone());
            continue;
        };

        child_groups
            .entry(first.to_string())
            .or_default()
            .push(TreeEntry {
                path: if path.is_empty() {
                    format!("{first}/{rest}")
                } else {
                    format!("{path}/{first}/{rest}")
                },
                ..entry.clone()
            });
    }

    let mut node_entries = Vec::new();

    for entry in direct_entries {
        if matches!(entry.kind, TreeEntryKind::Directory) {
            continue;
        }
        let name = entry
            .path
            .rsplit('/')
            .next()
            .unwrap_or(&entry.path)
            .to_string();
        let hash = entry
            .hash
            .clone()
            .ok_or_else(|| ModelValidationError::MissingFileHash(entry.path.clone()))?;
        let blob_id = entry
            .blob_id
            .clone()
            .unwrap_or_else(|| BlobId::from_hash(&hash));
        node_entries.push(TreeNodeEntry {
            name,
            kind: entry.kind,
            target: TreeNodeEntryTarget::Blob(blob_id),
            hash,
            size_bytes: entry.size_bytes,
            policy_id: entry.policy_id,
        });
    }

    for (child_name, child_entries) in child_groups {
        let child_path = if path.is_empty() {
            child_name.clone()
        } else {
            format!("{path}/{child_name}")
        };
        let child_node = build_tree_node_recursive(&child_path, &child_entries, nodes)?;
        node_entries.push(TreeNodeEntry {
            name: child_name,
            kind: TreeEntryKind::Directory,
            target: TreeNodeEntryTarget::Tree(child_node.id.clone()),
            hash: child_node.hash.clone(),
            size_bytes: None,
            policy_id: None,
        });
    }

    node_entries.sort_by(|a, b| a.name.cmp(&b.name));
    let node = TreeNode::new(path.to_string(), node_entries);
    nodes.push(node.clone());
    Ok(node)
}

pub fn compute_tree_node_hash(entries: &[TreeNodeEntry]) -> ContentHash {
    let mut encoded = String::new();
    for entry in entries {
        encoded.push_str(&entry.name);
        encoded.push('\0');
        encoded.push_str(match entry.kind {
            TreeEntryKind::File => "file",
            TreeEntryKind::Directory => "dir",
            TreeEntryKind::Symlink => "symlink",
            TreeEntryKind::Executable => "exec",
        });
        encoded.push('\0');
        encoded.push_str(&entry.hash.algorithm);
        encoded.push(':');
        encoded.push_str(&entry.hash.digest);
        encoded.push('\0');
        if let Some(size) = entry.size_bytes {
            encoded.push_str(&size.to_string());
        }
        encoded.push('\n');
    }
    ContentHash::sha256(encoded.as_bytes())
}

#[cfg(test)]
mod model_tests {
    use super::*;

    #[test]
    fn content_blob_id_is_derived_from_hash() {
        let blob = ContentBlob::from_bytes(
            b"hello",
            Some("text/plain".to_string()),
            BlobVisibility::Public,
        );

        assert_eq!(blob.id, BlobId::from_hash(&blob.hash));
        assert_eq!(blob.size_bytes, 5);
    }

    #[test]
    fn canonical_snapshot_sorts_entries_and_derives_id_from_root() {
        let a = ContentBlob::from_bytes(b"a", None, BlobVisibility::Public);
        let b = ContentBlob::from_bytes(b"b", None, BlobVisibility::Public);
        let snapshot = TreeSnapshot::canonical(
            RepositoryId::generated(),
            Vec::new(),
            vec![
                TreeEntry::file("src/b.ts", &b, None).unwrap(),
                TreeEntry::file("./src/a.ts", &a, None).unwrap(),
            ],
            BTreeMap::new(),
        )
        .unwrap();

        assert_eq!(snapshot.entries[0].path, "src/a.ts");
        assert_eq!(snapshot.entries[1].path, "src/b.ts");
        assert_eq!(
            snapshot.id,
            TreeSnapshotId::from_root_hash(&snapshot.root_hash)
        );
        assert_eq!(
            snapshot.root_tree_id,
            TreeNodeId::from_hash(&snapshot.root_hash)
        );
    }

    #[test]
    fn chunked_blob_splits_large_content() {
        let blob = ChunkedBlob::from_bytes(
            b"abcdef",
            Some("text/plain".to_string()),
            BlobVisibility::Public,
            2,
        );

        assert_eq!(blob.chunks.len(), 3);
        assert_eq!(blob.chunks[0].offset, 0);
        assert_eq!(blob.chunks[1].offset, 2);
        assert_eq!(blob.chunks[2].offset, 4);
    }

    #[test]
    fn tree_builder_reuses_unchanged_subtree_hashes() {
        let a = ContentBlob::from_bytes(b"a", None, BlobVisibility::Public);
        let b = ContentBlob::from_bytes(b"b", None, BlobVisibility::Public);
        let changed = ContentBlob::from_bytes(b"changed", None, BlobVisibility::Public);
        let first = build_tree_nodes(&[
            TreeEntry::file("src/a.ts", &a, None).unwrap(),
            TreeEntry::file("docs/b.md", &b, None).unwrap(),
        ])
        .unwrap();
        let second = build_tree_nodes(&[
            TreeEntry::file("src/a.ts", &changed, None).unwrap(),
            TreeEntry::file("docs/b.md", &b, None).unwrap(),
        ])
        .unwrap();
        let first_docs = first.iter().find(|n| n.path == "docs").unwrap();
        let second_docs = second.iter().find(|n| n.path == "docs").unwrap();
        let first_src = first.iter().find(|n| n.path == "src").unwrap();
        let second_src = second.iter().find(|n| n.path == "src").unwrap();

        assert_eq!(first_docs.hash, second_docs.hash);
        assert_ne!(first_src.hash, second_src.hash);
    }

    #[test]
    fn canonical_snapshot_rejects_duplicate_normalized_paths() {
        let blob = ContentBlob::from_bytes(b"a", None, BlobVisibility::Public);
        let result = TreeSnapshot::canonical(
            RepositoryId::generated(),
            Vec::new(),
            vec![
                TreeEntry::file("src/a.ts", &blob, None).unwrap(),
                TreeEntry::file("./src//a.ts", &blob, None).unwrap(),
            ],
            BTreeMap::new(),
        );

        assert!(
            matches!(result, Err(ModelValidationError::DuplicatePath(path)) if path == "src/a.ts")
        );
    }

    #[test]
    fn canonical_snapshot_rejects_file_directory_prefix_conflicts() {
        let blob = ContentBlob::from_bytes(b"a", None, BlobVisibility::Public);
        let result = TreeSnapshot::canonical(
            RepositoryId::generated(),
            Vec::new(),
            vec![
                TreeEntry::file("src", &blob, None).unwrap(),
                TreeEntry::file("src/a.ts", &blob, None).unwrap(),
            ],
            BTreeMap::new(),
        );

        assert!(matches!(
            result,
            Err(ModelValidationError::FilePathConflict(path)) if path == "src/a.ts"
        ));
    }

    #[test]
    fn normalizer_rejects_absolute_and_traversal_paths() {
        assert!(matches!(
            normalize_repo_path("/tmp/file"),
            Err(ModelValidationError::AbsolutePath(_))
        ));
        assert!(matches!(
            normalize_repo_path("../secret"),
            Err(ModelValidationError::PathTraversal(_))
        ));
    }

    #[test]
    fn telemetry_event_and_report_envelope_are_json_stable() {
        let context = NebulaTelemetryContext {
            repository_id: Some(RepositoryId::new("repo_123")),
            request_id: Some("req_123".to_string()),
            ..Default::default()
        };
        let event = NebulaTelemetryEvent {
            event_id: "evt_123".to_string(),
            event_type: "sync.session.validated".to_string(),
            source: TelemetrySource::Sync,
            severity: TelemetrySeverity::Info,
            message: "validated".to_string(),
            context: context.clone(),
            created_at_unix_ms: 42,
            attributes: BTreeMap::new(),
        };
        let event_json = serde_json::to_value(&event).unwrap();
        assert_eq!(event_json["event_type"], "sync.session.validated");
        assert_eq!(event_json["context"]["repository_id"], "repo_123");

        let report = NebulaOpsReportEnvelope {
            report_id: "report_123".to_string(),
            report_type: "consistency_check".to_string(),
            source: TelemetrySource::OpsCli,
            severity: TelemetrySeverity::Warning,
            context,
            created_at_unix_ms: 42,
            dry_run: true,
            outcome: "missing_blobs".to_string(),
            report: serde_json::json!({ "missing": 1 }),
            follow_up_actions: vec!["repair missing blob".to_string()],
        };
        let report_json = serde_json::to_value(&report).unwrap();
        assert_eq!(report_json["report_type"], "consistency_check");
        assert_eq!(report_json["dry_run"], true);
    }
}
