use crate::{
    Actor, ChangeSetId, OperationId, PolicyId, ProposalId, RefId, RepositoryId, TreeSnapshotId,
    WorkspaceId,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct Operation {
    pub id: OperationId,
    pub repository_id: RepositoryId,
    pub parent_operation_ids: Vec<OperationId>,
    pub actor: Actor,
    pub timestamp_unix_ms: u64,
    pub kind: OperationKind,
    pub input_view: OperationView,
    pub output_view: OperationView,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub enum OperationKind {
    InitRepository,
    SaveWorkspace,
    CreateWorkspace,
    SwitchWorkspace,
    CreateProposal,
    UpdateProposal,
    UpdateRef,
    UpdatePolicy,
    CreateProjection,
}

#[derive(Clone, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct OperationView {
    pub snapshot_ids: Vec<TreeSnapshotId>,
    pub ref_ids: Vec<RefId>,
    pub workspace_ids: Vec<WorkspaceId>,
    pub changeset_ids: Vec<ChangeSetId>,
    pub proposal_ids: Vec<ProposalId>,
    pub policy_ids: Vec<PolicyId>,
}

impl Operation {
    pub fn new(
        repository_id: RepositoryId,
        parent_operation_ids: Vec<OperationId>,
        actor: Actor,
        timestamp_unix_ms: u64,
        kind: OperationKind,
        input_view: OperationView,
        output_view: OperationView,
    ) -> Self {
        Self {
            id: OperationId::generated(),
            repository_id,
            parent_operation_ids,
            actor,
            timestamp_unix_ms,
            kind,
            input_view,
            output_view,
        }
    }
}
