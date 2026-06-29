use crate::{ChangeSetId, NebulaResult, RepositoryId, TreeSnapshotId};
use async_trait::async_trait;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct AffectedGraph {
    pub changeset_id: Option<ChangeSetId>,
    pub repository_id: RepositoryId,
    pub snapshot_id: TreeSnapshotId,
    pub changed_paths: Vec<String>,
    pub affected_targets: Vec<String>,
    pub affected_tests: Vec<String>,
}

#[async_trait]
pub trait BuildGraphProvider: Send + Sync {
    async fn affected_graph(
        &self,
        repository_id: RepositoryId,
        snapshot_id: TreeSnapshotId,
        changed_paths: Vec<String>,
    ) -> NebulaResult<AffectedGraph>;
}
