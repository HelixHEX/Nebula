use async_trait::async_trait;
use nebula_core::{
    Actor, ContentHash, Environment, ProjectionId, ProposalId, RepositoryId, TreeSnapshot,
    TreeSnapshotId,
};
use nebula_git::{GitProjectionPlan, MaterializedProjection, materialize_projection};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fs, path::PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum BuildSourceError {
    #[error("source provider failed: {0}")]
    Provider(String),
    #[error("projection materialization failed: {0}")]
    Projection(String),
    #[error("invalid build source context: {0}")]
    InvalidContext(String),
    #[error("unsupported build source: {0}")]
    Unsupported(String),
}

pub type BuildSourceResult<T> = Result<T, BuildSourceError>;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum BuildSourceKind {
    GitHub,
    Nebula,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GitHubBuildSource {
    pub repo_full_name: String,
    pub branch: Option<String>,
    pub commit_sha: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NebulaBuildSource {
    pub galaxy_id: RepositoryId,
    pub snapshot_id: Option<TreeSnapshotId>,
    pub ref_name: Option<String>,
    pub projection_id: Option<ProjectionId>,
    pub environment: Environment,
    pub actor: Actor,
    pub path_scope: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum BuildSource {
    GitHub(GitHubBuildSource),
    Nebula(NebulaBuildSource),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BuildSourceRequest {
    pub service_name: String,
    pub source: BuildSource,
    pub build_dir: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ResolvedSource {
    pub kind: BuildSourceKind,
    pub source_label: String,
    pub build_dir: PathBuf,
    pub image_labels: BTreeMap<String, String>,
}

#[async_trait]
pub trait SourceProvider: Send + Sync {
    async fn prepare(&self, request: BuildSourceRequest) -> BuildSourceResult<ResolvedSource>;
}

#[derive(Clone, Debug, Default)]
pub struct GitHubSourceProvider;

#[async_trait]
impl SourceProvider for GitHubSourceProvider {
    async fn prepare(&self, request: BuildSourceRequest) -> BuildSourceResult<ResolvedSource> {
        let BuildSource::GitHub(source) = request.source else {
            return Err(BuildSourceError::Provider(
                "GitHubSourceProvider received non-GitHub source".to_string(),
            ));
        };
        Err(BuildSourceError::Unsupported(format!(
            "GitHub source `{}` requires a production checkout provider; use a Nebula projection build source until one is configured",
            source.repo_full_name
        )))
    }
}

#[derive(Clone, Debug)]
pub struct NebulaProjectionBuildContext {
    pub source: NebulaBuildSource,
    pub snapshot: TreeSnapshot,
    pub plan: GitProjectionPlan,
    pub blob_bytes: BTreeMap<ContentHash, Vec<u8>>,
}

#[derive(Clone, Debug)]
pub struct NebulaSourceProvider {
    context: NebulaProjectionBuildContext,
}

impl NebulaSourceProvider {
    pub fn new(context: NebulaProjectionBuildContext) -> Self {
        Self { context }
    }
}

#[async_trait]
impl SourceProvider for NebulaSourceProvider {
    async fn prepare(&self, request: BuildSourceRequest) -> BuildSourceResult<ResolvedSource> {
        let BuildSource::Nebula(source) = request.source else {
            return Err(BuildSourceError::Provider(
                "NebulaSourceProvider received non-Nebula source".to_string(),
            ));
        };
        validate_nebula_build_context(&source, &self.context, &request.build_dir)?;
        let materialized = materialize_projection(
            &self.context.plan,
            &self.context.snapshot,
            &self.context.blob_bytes,
            &request.build_dir,
        )
        .map_err(|error| BuildSourceError::Projection(error.to_string()))?;
        Ok(resolved_nebula_source(
            source,
            &self.context.snapshot,
            materialized,
        ))
    }
}

fn validate_nebula_build_context(
    source: &NebulaBuildSource,
    context: &NebulaProjectionBuildContext,
    build_dir: &PathBuf,
) -> BuildSourceResult<()> {
    if source != &context.source {
        return Err(BuildSourceError::InvalidContext(
            "request source does not match provider context".to_string(),
        ));
    }
    if source.galaxy_id != context.snapshot.repository_id {
        return Err(BuildSourceError::InvalidContext(
            "source repository does not match snapshot repository".to_string(),
        ));
    }
    if source
        .snapshot_id
        .as_ref()
        .is_some_and(|snapshot_id| snapshot_id != &context.snapshot.id)
    {
        return Err(BuildSourceError::InvalidContext(
            "source snapshot does not match materialized snapshot".to_string(),
        ));
    }
    if build_dir.exists()
        && build_dir
            .read_dir()
            .map_err(|error| {
                BuildSourceError::InvalidContext(format!("failed to inspect build dir: {error}"))
            })?
            .next()
            .is_some()
    {
        return Err(BuildSourceError::InvalidContext(
            "build directory must be empty before materialization".to_string(),
        ));
    }
    fs::create_dir_all(build_dir).map_err(|error| {
        BuildSourceError::InvalidContext(format!("failed to create build dir: {error}"))
    })?;
    Ok(())
}

fn resolved_nebula_source(
    source: NebulaBuildSource,
    snapshot: &TreeSnapshot,
    materialized: MaterializedProjection,
) -> ResolvedSource {
    ResolvedSource {
        kind: BuildSourceKind::Nebula,
        source_label: source
            .projection_id
            .as_ref()
            .map(|id| id.as_str().to_string())
            .unwrap_or_else(|| snapshot.id.as_str().to_string()),
        build_dir: materialized.root,
        image_labels: BTreeMap::from([
            (
                "nebula.galaxy_id".to_string(),
                source.galaxy_id.as_str().to_string(),
            ),
            (
                "nebula.snapshot_id".to_string(),
                snapshot.id.as_str().to_string(),
            ),
            (
                "nebula.root_hash".to_string(),
                format!(
                    "{}:{}",
                    snapshot.root_hash.algorithm, snapshot.root_hash.digest
                ),
            ),
            (
                "nebula.environment".to_string(),
                source.environment.name.clone(),
            ),
        ]),
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum BuildTriggerEvent {
    ProposalMerged {
        proposal_id: ProposalId,
    },
    RefUpdated {
        galaxy_id: RepositoryId,
        ref_name: String,
    },
    ProjectionReady {
        projection_id: ProjectionId,
    },
    ReleaseGateOpened {
        galaxy_id: RepositoryId,
        gate_id: String,
    },
    ExplicitDeploy {
        requested_by: Actor,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PreviewEnvironmentPlan {
    pub proposal_id: ProposalId,
    pub environment_name: String,
    pub source: NebulaBuildSource,
}

pub fn preview_environment_for_proposal(
    proposal_id: ProposalId,
    source: NebulaBuildSource,
) -> PreviewEnvironmentPlan {
    let short = proposal_id
        .as_str()
        .rsplit('_')
        .next()
        .unwrap_or(proposal_id.as_str())
        .chars()
        .take(8)
        .collect::<String>();
    PreviewEnvironmentPlan {
        proposal_id,
        environment_name: format!("proposal-{short}"),
        source,
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GitOpsHandoff {
    pub commit_message: String,
    pub source_uri: String,
    pub projection_id: Option<ProjectionId>,
    pub image_ref: String,
    pub image_labels: BTreeMap<String, String>,
}

pub fn gitops_handoff_for_nebula_source(
    source: &NebulaBuildSource,
    snapshot: &TreeSnapshot,
    image_ref: impl Into<String>,
) -> GitOpsHandoff {
    let projection_id = source.projection_id.clone();
    let source_uri = format!(
        "nebula://galaxy/{}/snapshot/{}",
        source.galaxy_id.as_str(),
        snapshot.id.as_str()
    );
    GitOpsHandoff {
        commit_message: format!(
            "deploy({}): {} {}",
            source.environment.name,
            source.galaxy_id.as_str(),
            snapshot.id.as_str()
        ),
        source_uri,
        projection_id: projection_id.clone(),
        image_ref: image_ref.into(),
        image_labels: resolved_nebula_source(
            source.clone(),
            snapshot,
            MaterializedProjection {
                root: PathBuf::new(),
                written_paths: Vec::new(),
                omitted_paths: Vec::new(),
            },
        )
        .image_labels,
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum DeployTriggerMode {
    AstracollabExplicitCall,
    NebulaWebhook,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DeployTriggerPlan {
    pub mode: DeployTriggerMode,
    pub event: BuildTriggerEvent,
    pub source: NebulaBuildSource,
}

pub fn explicit_deploy_trigger(
    source: NebulaBuildSource,
    requested_by: Actor,
) -> DeployTriggerPlan {
    DeployTriggerPlan {
        mode: DeployTriggerMode::AstracollabExplicitCall,
        event: BuildTriggerEvent::ExplicitDeploy { requested_by },
        source,
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GitCompatibilityAssessment {
    pub should_build_canonical_provider_first: bool,
    pub useful_for_legacy_hosts: bool,
    pub concerns: Vec<String>,
}

pub fn assess_git_compatibility_remote() -> GitCompatibilityAssessment {
    GitCompatibilityAssessment {
        should_build_canonical_provider_first: true,
        useful_for_legacy_hosts: true,
        concerns: vec![
            "Git compatibility can hide policy decisions behind a clone abstraction".to_string(),
            "Large Galaxy projections need sparse/blobless modes to avoid Git-scale pain"
                .to_string(),
            "Canonical builds should prefer policy-aware Nebula projections".to_string(),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn github_source_provider_is_explicitly_unsupported_without_checkout_backend() {
        let provider = GitHubSourceProvider;
        let result = provider
            .prepare(BuildSourceRequest {
                service_name: "web".to_string(),
                source: BuildSource::GitHub(GitHubBuildSource {
                    repo_full_name: "astracollab/app".to_string(),
                    branch: Some("main".to_string()),
                    commit_sha: None,
                }),
                build_dir: PathBuf::from("build"),
            })
            .await;

        assert!(matches!(result, Err(BuildSourceError::Unsupported(_))));
    }
}
