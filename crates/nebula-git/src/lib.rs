use nebula_core::{
    Actor, BlobVisibility, ContentBlob, ContentHash, Environment, GitExport, GitExportId,
    GitMigrationRecord, GitMigrationRecordId, PolicyDecision, Projection, ProjectionId,
    ProjectionManifest, ProjectionTarget, Proposal, Ref, RefId, RefTarget, RepositoryId, TreeEntry,
    TreeEntryKind, TreeSnapshot, TreeSnapshotId,
};
use serde::{Deserialize, Serialize};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt::{Display, Formatter},
    fs,
    path::{Path, PathBuf},
    process::Command,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum GitProjectionAction {
    Include {
        path: String,
    },
    Redact {
        path: String,
        replacement_path: Option<String>,
    },
    Template {
        path: String,
        template_path: String,
    },
    Omit {
        path: String,
    },
    Block {
        path: String,
        reason: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GitProjectionPlan {
    pub projection: Projection,
    pub manifest: ProjectionManifest,
    pub actions: Vec<GitProjectionAction>,
}

impl GitProjectionPlan {
    pub fn has_blockers(&self) -> bool {
        self.actions
            .iter()
            .any(|action| matches!(action, GitProjectionAction::Block { .. }))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GitProjectionRequest {
    pub actor: Actor,
    pub environment: Environment,
    pub target: ProjectionTarget,
    pub path_decisions: BTreeMap<String, PolicyDecision>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GitProjectionPreview {
    pub manifest: ProjectionManifest,
    pub actions: Vec<GitProjectionAction>,
    pub has_blockers: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GitImportPlan {
    pub remote: String,
    pub imported_refs: Vec<String>,
    pub preserves_history: bool,
    pub supports_lfs: bool,
    pub metadata: GitImportMetadata,
    pub commands: Vec<GitCommandPlan>,
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GitExportPlan {
    pub remote: String,
    pub branch: String,
    pub snapshot_id: String,
    pub included_paths: Vec<String>,
    pub omitted_paths: Vec<String>,
    pub signed: bool,
    pub lfs_compatible: bool,
    pub metadata: GitExportMetadata,
    pub commands: Vec<GitCommandPlan>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GitHubPrPlan {
    pub proposal_id: String,
    pub branch: String,
    pub title: String,
    pub body: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct GitAuthorMetadata {
    pub name: String,
    pub email: String,
    pub timestamp_unix_ms: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GitTagMetadata {
    pub name: String,
    pub target: String,
    pub annotation: Option<String>,
    pub signed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GitLfsPointer {
    pub path: String,
    pub oid_sha256: String,
    pub size_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GitModeMetadata {
    pub path: String,
    pub mode: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct GitImportMetadata {
    pub author: Option<GitAuthorMetadata>,
    pub tags: Vec<GitTagMetadata>,
    pub lfs_pointers: Vec<GitLfsPointer>,
    #[serde(default)]
    pub modes: Vec<GitModeMetadata>,
    #[serde(default)]
    pub symlinks: Vec<String>,
    #[serde(default)]
    pub submodules: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GitExportSignature {
    pub signer: String,
    pub algorithm: String,
    pub payload_digest: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct GitExportMetadata {
    pub author: Option<GitAuthorMetadata>,
    pub tags: Vec<GitTagMetadata>,
    pub lfs_pointers: Vec<GitLfsPointer>,
    #[serde(default)]
    pub modes: Vec<GitModeMetadata>,
    #[serde(default)]
    pub symlinks: Vec<String>,
    #[serde(default)]
    pub submodules: Vec<String>,
    pub signature: Option<GitExportSignature>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GitCommandPlan {
    pub program: String,
    pub args: Vec<String>,
    pub cwd: Option<PathBuf>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GitCommandOutput {
    pub program: String,
    pub args: Vec<String>,
    pub status_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GitExecutionResult {
    pub commands: Vec<GitCommandOutput>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GitImportExecution {
    pub mirror_path: PathBuf,
    pub refs: Vec<String>,
    pub tags: Vec<GitTagMetadata>,
    pub result: GitExecutionResult,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum GitLfsStrategy {
    Pointers,
    Download,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GitMigrationOptions {
    pub repository_id: RepositoryId,
    pub ref_namespace: String,
    pub lfs_strategy: GitLfsStrategy,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GitCommitMetadata {
    pub sha: String,
    pub tree_sha: String,
    pub parent_shas: Vec<String>,
    pub author: GitAuthorMetadata,
    pub committer: GitAuthorMetadata,
    pub message: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GitRefMapping {
    pub git_ref: String,
    pub nebula_ref: Ref,
    pub git_commit_sha: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GitMigratedBlob {
    pub blob: ContentBlob,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GitMigrationOutput {
    pub repository_id: RepositoryId,
    pub snapshots: Vec<TreeSnapshot>,
    pub migration_records: Vec<GitMigrationRecord>,
    pub refs: Vec<GitRefMapping>,
    pub blobs: Vec<GitMigratedBlob>,
    pub commit_to_snapshot: BTreeMap<String, TreeSnapshotId>,
    pub tags: Vec<GitTagMetadata>,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GitMigrationVerification {
    pub valid: bool,
    pub checked_commits: usize,
    pub checked_refs: usize,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GitProjectionError {
    MissingPolicyDecision { path: String },
    BlockedProjection { paths: Vec<String> },
    MissingBlob { path: String, hash: ContentHash },
    UnsafePath { path: String },
    Unsupported { message: String },
    InvalidGitObject { message: String },
    Io { message: String },
}

impl Display for GitProjectionError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingPolicyDecision { path } => {
                write!(f, "missing policy decision for path `{path}`")
            }
            Self::BlockedProjection { paths } => {
                write!(f, "projection has blocked path(s): {}", paths.join(", "))
            }
            Self::MissingBlob { path, hash } => {
                write!(f, "missing blob bytes for `{path}` ({hash:?})")
            }
            Self::UnsafePath { path } => write!(f, "unsafe projection path `{path}`"),
            Self::Unsupported { message } | Self::InvalidGitObject { message } => {
                f.write_str(message)
            }
            Self::Io { message } => f.write_str(message),
        }
    }
}

impl Error for GitProjectionError {}

pub fn plan_git_projection(
    snapshot: &TreeSnapshot,
    proposal: &Proposal,
    request: GitProjectionRequest,
) -> Result<GitProjectionPlan, GitProjectionError> {
    let actions = projection_actions(snapshot, &request.path_decisions)?;
    let projection = Projection {
        id: ProjectionId::generated(),
        repository_id: snapshot.repository_id.clone(),
        snapshot_id: snapshot.id.clone(),
        environment_id: request.environment.id,
        target: request.target,
        actor: request.actor,
        policy_checks: proposal.policy_checks.clone(),
    };
    let manifest = manifest_from_actions(&projection, snapshot, &actions);

    Ok(GitProjectionPlan {
        projection,
        manifest,
        actions,
    })
}

pub fn preview_git_projection(
    snapshot: &TreeSnapshot,
    proposal: &Proposal,
    request: GitProjectionRequest,
) -> Result<GitProjectionPreview, GitProjectionError> {
    let plan = plan_git_projection(snapshot, proposal, request)?;
    Ok(GitProjectionPreview {
        has_blockers: plan.has_blockers(),
        manifest: plan.manifest,
        actions: plan.actions,
    })
}

pub fn plan_github_projection(
    snapshot: &TreeSnapshot,
    proposal: &Proposal,
    actor: Actor,
    environment: Environment,
    path_decisions: BTreeMap<String, PolicyDecision>,
) -> Result<GitProjectionPlan, GitProjectionError> {
    plan_git_projection(
        snapshot,
        proposal,
        GitProjectionRequest {
            actor,
            environment,
            target: ProjectionTarget::GitHub,
            path_decisions,
        },
    )
}

pub fn plan_git_import(remote: impl Into<String>) -> GitImportPlan {
    let remote = remote.into();
    GitImportPlan {
        remote: remote.clone(),
        imported_refs: vec!["refs/heads/*".to_string(), "refs/tags/*".to_string()],
        preserves_history: false,
        supports_lfs: false,
        metadata: GitImportMetadata::default(),
        commands: vec![
            GitCommandPlan {
                program: "git".to_string(),
                args: vec!["clone".to_string(), "--mirror".to_string(), remote],
                cwd: None,
            },
            GitCommandPlan {
                program: "git".to_string(),
                args: vec!["lfs".to_string(), "fetch".to_string(), "--all".to_string()],
                cwd: None,
            },
        ],
        notes: vec![
            "Current import support creates a Git mirror for inspection only".to_string(),
            "Converting Git commits, trees, LFS objects, and submodules into Nebula snapshots is not production-supported yet".to_string(),
        ],
    }
}

pub fn execute_git_import(
    remote: impl Into<String>,
    mirror_path: impl AsRef<Path>,
) -> Result<GitImportExecution, GitProjectionError> {
    let remote = remote.into();
    let mirror_path = mirror_path.as_ref().to_path_buf();
    let clone = GitCommandPlan {
        program: "git".to_string(),
        args: vec![
            "clone".to_string(),
            "--mirror".to_string(),
            remote,
            mirror_path.display().to_string(),
        ],
        cwd: None,
    };
    let result = execute_git_commands(&[clone])?;
    let refs = git_lines(
        &mirror_path,
        &[
            "for-each-ref",
            "--format=%(refname)",
            "refs/heads",
            "refs/tags",
        ],
    )?;
    let tags = git_lines(
        &mirror_path,
        &[
            "for-each-ref",
            "--format=%(refname:short)|%(objectname)|%(contents:subject)",
            "refs/tags",
        ],
    )?
    .into_iter()
    .filter_map(|line| {
        let mut parts = line.splitn(3, '|');
        Some(GitTagMetadata {
            name: parts.next()?.to_string(),
            target: parts.next().unwrap_or_default().to_string(),
            annotation: parts
                .next()
                .filter(|value| !value.is_empty())
                .map(ToString::to_string),
            signed: false,
        })
    })
    .collect();
    Ok(GitImportExecution {
        mirror_path,
        refs,
        tags,
        result,
    })
}

pub trait GitObjectReader {
    fn commit_shas(&self) -> Result<Vec<String>, GitProjectionError>;
    fn read_commit(&self, sha: &str) -> Result<GitCommitMetadata, GitProjectionError>;
    fn tree_entries(&self, sha: &str) -> Result<Vec<GitTreeEntry>, GitProjectionError>;
    fn blob_bytes(&self, sha: &str) -> Result<Vec<u8>, GitProjectionError>;
    fn refs(&self) -> Result<Vec<(String, String)>, GitProjectionError>;
    fn tags(&self) -> Result<Vec<GitTagMetadata>, GitProjectionError>;
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GitTreeEntry {
    pub mode: String,
    pub object_type: String,
    pub sha: String,
    pub path: String,
}

#[derive(Clone, Debug)]
pub struct GitCliReader {
    repo: PathBuf,
}

impl GitCliReader {
    pub fn new(repo: impl AsRef<Path>) -> Self {
        Self {
            repo: repo.as_ref().to_path_buf(),
        }
    }
}

impl GitObjectReader for GitCliReader {
    fn commit_shas(&self) -> Result<Vec<String>, GitProjectionError> {
        git_lines(
            &self.repo,
            &["rev-list", "--topo-order", "--reverse", "--all"],
        )
    }

    fn read_commit(&self, sha: &str) -> Result<GitCommitMetadata, GitProjectionError> {
        let raw = git_bytes(
            &self.repo,
            &[
                "show",
                "-s",
                "--format=%H%x00%T%x00%P%x00%an%x00%ae%x00%at%x00%cn%x00%ce%x00%ct%x00%B",
                sha,
            ],
        )?;
        let text =
            String::from_utf8(raw).map_err(|error| GitProjectionError::InvalidGitObject {
                message: format!("commit metadata is not UTF-8 for {sha}: {error}"),
            })?;
        let parts = text.splitn(10, '\0').collect::<Vec<_>>();
        if parts.len() != 10 {
            return Err(GitProjectionError::InvalidGitObject {
                message: format!("unexpected commit metadata shape for {sha}"),
            });
        }
        Ok(GitCommitMetadata {
            sha: parts[0].trim().to_string(),
            tree_sha: parts[1].trim().to_string(),
            parent_shas: parts[2]
                .split_whitespace()
                .map(ToString::to_string)
                .collect(),
            author: GitAuthorMetadata {
                name: parts[3].to_string(),
                email: parts[4].to_string(),
                timestamp_unix_ms: parts[5]
                    .trim()
                    .parse::<u64>()
                    .ok()
                    .map(|seconds| seconds * 1000),
            },
            committer: GitAuthorMetadata {
                name: parts[6].to_string(),
                email: parts[7].to_string(),
                timestamp_unix_ms: parts[8]
                    .trim()
                    .parse::<u64>()
                    .ok()
                    .map(|seconds| seconds * 1000),
            },
            message: parts[9].trim_end().to_string(),
        })
    }

    fn tree_entries(&self, sha: &str) -> Result<Vec<GitTreeEntry>, GitProjectionError> {
        let raw = git_bytes(&self.repo, &["ls-tree", "-rz", "-t", sha])?;
        raw.split(|byte| *byte == 0)
            .filter(|entry| !entry.is_empty())
            .map(parse_git_tree_entry)
            .collect()
    }

    fn blob_bytes(&self, sha: &str) -> Result<Vec<u8>, GitProjectionError> {
        git_bytes(&self.repo, &["cat-file", "-p", sha])
    }

    fn refs(&self) -> Result<Vec<(String, String)>, GitProjectionError> {
        let refs = git_lines(
            &self.repo,
            &[
                "for-each-ref",
                "--format=%(refname)|%(*objectname)|%(objectname)",
                "refs/heads",
                "refs/tags",
            ],
        )?
        .into_iter()
        .filter_map(|line| {
            let mut parts = line.splitn(3, '|');
            let name = parts.next()?;
            let peeled = parts.next().unwrap_or_default();
            let object = parts.next().unwrap_or_default();
            Some((
                name.to_string(),
                if peeled.is_empty() { object } else { peeled }.to_string(),
            ))
        })
        .collect::<Vec<_>>();
        Ok(refs)
    }

    fn tags(&self) -> Result<Vec<GitTagMetadata>, GitProjectionError> {
        let tags = git_lines(
            &self.repo,
            &[
                "for-each-ref",
                "--format=%(refname:short)|%(objectname)|%(contents:subject)",
                "refs/tags",
            ],
        )?
        .into_iter()
        .filter_map(|line| {
            let mut parts = line.splitn(3, '|');
            Some(GitTagMetadata {
                name: parts.next()?.to_string(),
                target: parts.next().unwrap_or_default().to_string(),
                annotation: parts
                    .next()
                    .filter(|value| !value.is_empty())
                    .map(ToString::to_string),
                signed: false,
            })
        })
        .collect::<Vec<_>>();
        Ok(tags)
    }
}

fn parse_git_tree_entry(raw: &[u8]) -> Result<GitTreeEntry, GitProjectionError> {
    let text =
        String::from_utf8(raw.to_vec()).map_err(|error| GitProjectionError::InvalidGitObject {
            message: format!("tree entry is not UTF-8: {error}"),
        })?;
    let (header, path) =
        text.split_once('\t')
            .ok_or_else(|| GitProjectionError::InvalidGitObject {
                message: format!("malformed tree entry `{text}`"),
            })?;
    let mut header = header.split_whitespace();
    let mode = header
        .next()
        .ok_or_else(|| GitProjectionError::InvalidGitObject {
            message: "tree entry missing mode".to_string(),
        })?
        .to_string();
    let object_type = header
        .next()
        .ok_or_else(|| GitProjectionError::InvalidGitObject {
            message: "tree entry missing object type".to_string(),
        })?
        .to_string();
    let sha = header
        .next()
        .ok_or_else(|| GitProjectionError::InvalidGitObject {
            message: "tree entry missing object sha".to_string(),
        })?
        .to_string();
    Ok(GitTreeEntry {
        mode,
        object_type,
        sha,
        path: path.to_string(),
    })
}

fn snapshot_entries_for_commit<R: GitObjectReader>(
    reader: &R,
    commit: &GitCommitMetadata,
    blobs: &mut BTreeMap<ContentHash, GitMigratedBlob>,
) -> Result<(Vec<TreeEntry>, BTreeMap<String, String>), GitProjectionError> {
    let mut entries = Vec::new();
    let mut metadata = BTreeMap::from([
        ("git_commit_sha".to_string(), commit.sha.clone()),
        ("git_tree_sha".to_string(), commit.tree_sha.clone()),
        ("git_author_name".to_string(), commit.author.name.clone()),
        ("git_author_email".to_string(), commit.author.email.clone()),
        (
            "git_author_time_unix_ms".to_string(),
            commit
                .author
                .timestamp_unix_ms
                .unwrap_or_default()
                .to_string(),
        ),
        (
            "git_committer_name".to_string(),
            commit.committer.name.clone(),
        ),
        (
            "git_committer_email".to_string(),
            commit.committer.email.clone(),
        ),
        (
            "git_committer_time_unix_ms".to_string(),
            commit
                .committer
                .timestamp_unix_ms
                .unwrap_or_default()
                .to_string(),
        ),
        ("git_message".to_string(), commit.message.clone()),
    ]);
    for parent in &commit.parent_shas {
        metadata.insert(format!("git_parent.{parent}"), parent.clone());
    }
    for entry in reader.tree_entries(&commit.sha)? {
        match entry.object_type.as_str() {
            "tree" => entries.push(TreeEntry::directory(entry.path).map_err(|error| {
                GitProjectionError::InvalidGitObject {
                    message: error.to_string(),
                }
            })?),
            "blob" => {
                let bytes = reader.blob_bytes(&entry.sha)?;
                let blob = ContentBlob::from_bytes(&bytes, None, BlobVisibility::Public);
                let kind = match entry.mode.as_str() {
                    "100755" => TreeEntryKind::Executable,
                    "120000" => TreeEntryKind::Symlink,
                    _ => TreeEntryKind::File,
                };
                if let Some(pointer) =
                    detect_lfs_pointers(&BTreeMap::from([(entry.path.clone(), bytes.clone())]))
                        .into_iter()
                        .next()
                {
                    metadata.insert(
                        format!("git_lfs_pointer.{}", entry.path),
                        format!("{}:{}", pointer.oid_sha256, pointer.size_bytes),
                    );
                }
                entries.push(TreeEntry {
                    path: entry.path,
                    kind,
                    blob_id: Some(blob.id.clone()),
                    hash: Some(blob.hash.clone()),
                    size_bytes: Some(blob.size_bytes),
                    policy_id: None,
                });
                blobs
                    .entry(blob.hash.clone())
                    .or_insert(GitMigratedBlob { blob, bytes });
            }
            "commit" => {
                metadata.insert(format!("git_submodule.{}", entry.path), entry.sha);
            }
            _ => {
                return Err(GitProjectionError::InvalidGitObject {
                    message: format!("unsupported git tree object type `{}`", entry.object_type),
                });
            }
        }
    }
    Ok((entries, metadata))
}

fn migration_ref_name(namespace: &str, git_ref: &str) -> String {
    let namespace = namespace.trim_matches('/');
    if let Some(branch) = git_ref.strip_prefix("refs/heads/") {
        format!("{namespace}/{branch}")
    } else if let Some(tag) = git_ref.strip_prefix("refs/tags/") {
        format!("{namespace}/tags/{tag}")
    } else {
        format!("{namespace}/{}", git_ref.trim_start_matches("refs/"))
    }
}

pub fn migrate_git_repository(
    repo: impl AsRef<Path>,
    options: GitMigrationOptions,
) -> Result<GitMigrationOutput, GitProjectionError> {
    if matches!(options.lfs_strategy, GitLfsStrategy::Download) {
        return Err(GitProjectionError::Unsupported {
            message: "LFS download migration requires a production LFS fetcher; use --lfs=pointers"
                .to_string(),
        });
    }
    migrate_git_reader(&GitCliReader::new(repo), options)
}

pub fn migrate_git_reader<R: GitObjectReader>(
    reader: &R,
    options: GitMigrationOptions,
) -> Result<GitMigrationOutput, GitProjectionError> {
    let mut commit_to_snapshot = BTreeMap::new();
    let mut snapshots = Vec::new();
    let mut migration_records = Vec::new();
    let mut blobs = BTreeMap::<ContentHash, GitMigratedBlob>::new();
    let mut warnings = Vec::new();
    for sha in reader.commit_shas()? {
        let commit = reader.read_commit(&sha)?;
        let (entries, metadata) = snapshot_entries_for_commit(reader, &commit, &mut blobs)?;
        let parent_snapshot_ids = commit
            .parent_shas
            .iter()
            .filter_map(|parent| commit_to_snapshot.get(parent).cloned())
            .collect::<Vec<_>>();
        if parent_snapshot_ids.len() != commit.parent_shas.len() {
            warnings.push(format!(
                "commit {} has parent(s) outside migrated ref set",
                commit.sha
            ));
        }
        let submodule_paths = metadata
            .keys()
            .filter_map(|key| key.strip_prefix("git_submodule.").map(ToString::to_string))
            .collect::<Vec<_>>();
        let lfs_pointer_paths = metadata
            .keys()
            .filter_map(|key| {
                key.strip_prefix("git_lfs_pointer.")
                    .map(ToString::to_string)
            })
            .collect::<Vec<_>>();
        let mut snapshot = TreeSnapshot::canonical(
            options.repository_id.clone(),
            parent_snapshot_ids,
            entries,
            metadata,
        )
        .map_err(|error| GitProjectionError::InvalidGitObject {
            message: error.to_string(),
        })?;
        let migration_id_hash = ContentHash::sha256(
            format!("git-commit:{}:{}", options.repository_id, commit.sha).as_bytes(),
        );
        snapshot.id = TreeSnapshotId::new(format!("snap_git_{}", migration_id_hash.digest));
        let tag_names = reader
            .tags()?
            .into_iter()
            .filter(|tag| tag.target == commit.sha)
            .map(|tag| tag.name)
            .collect::<Vec<_>>();
        migration_records.push(GitMigrationRecord {
            id: GitMigrationRecordId::generated(),
            repository_id: options.repository_id.clone(),
            git_commit_sha: commit.sha.clone(),
            git_tree_sha: commit.tree_sha.clone(),
            parent_commit_shas: commit.parent_shas.clone(),
            snapshot_id: snapshot.id.clone(),
            author_name: commit.author.name.clone(),
            author_email: commit.author.email.clone(),
            committer_name: commit.committer.name.clone(),
            committer_email: commit.committer.email.clone(),
            message: commit.message.clone(),
            tag_names,
            submodule_paths,
            lfs_pointer_paths,
            signature_status: None,
        });
        commit_to_snapshot.insert(commit.sha.clone(), snapshot.id.clone());
        snapshots.push(snapshot);
    }
    let refs = reader
        .refs()?
        .into_iter()
        .filter_map(|(git_ref, object_sha)| {
            let snapshot_id = commit_to_snapshot.get(&object_sha)?;
            let nebula_name = migration_ref_name(&options.ref_namespace, &git_ref);
            Some(GitRefMapping {
                git_ref,
                git_commit_sha: object_sha,
                nebula_ref: Ref {
                    id: RefId::generated(),
                    repository_id: options.repository_id.clone(),
                    name: nebula_name,
                    target: RefTarget::Snapshot(snapshot_id.clone()),
                    policy_id: None,
                },
            })
        })
        .collect();
    Ok(GitMigrationOutput {
        repository_id: options.repository_id,
        snapshots,
        migration_records,
        refs,
        blobs: blobs.into_values().collect(),
        commit_to_snapshot,
        tags: reader.tags()?,
        warnings,
    })
}

pub fn verify_git_migration(output: &GitMigrationOutput) -> GitMigrationVerification {
    let snapshot_ids = output
        .snapshots
        .iter()
        .map(|snapshot| snapshot.id.clone())
        .collect::<BTreeSet<_>>();
    let blob_hashes = output
        .blobs
        .iter()
        .map(|blob| blob.blob.hash.clone())
        .collect::<BTreeSet<_>>();
    let mut errors = Vec::new();
    for snapshot in &output.snapshots {
        for parent in &snapshot.parent_snapshot_ids {
            if !snapshot_ids.contains(parent) {
                errors.push(format!(
                    "snapshot {} references missing parent {}",
                    snapshot.id, parent
                ));
            }
        }
        if !snapshot.metadata.contains_key("git_commit_sha") {
            errors.push(format!(
                "snapshot {} is missing git_commit_sha",
                snapshot.id
            ));
        }
        for entry in &snapshot.entries {
            if let Some(hash) = &entry.hash {
                if !blob_hashes.contains(hash) {
                    errors.push(format!(
                        "snapshot {} entry {} references missing blob {}:{}",
                        snapshot.id, entry.path, hash.algorithm, hash.digest
                    ));
                }
            }
        }
    }
    for mapping in &output.refs {
        if !matches!(&mapping.nebula_ref.target, RefTarget::Snapshot(id) if snapshot_ids.contains(id))
        {
            errors.push(format!(
                "ref {} points to missing snapshot",
                mapping.nebula_ref.name
            ));
        }
    }
    GitMigrationVerification {
        valid: errors.is_empty(),
        checked_commits: output.commit_to_snapshot.len(),
        checked_refs: output.refs.len(),
        warnings: output.warnings.clone(),
        errors,
    }
}

pub fn plan_git_export(
    snapshot: &TreeSnapshot,
    manifest: &ProjectionManifest,
    remote: impl Into<String>,
    branch: impl Into<String>,
) -> GitExportPlan {
    let remote = remote.into();
    let branch = branch.into();
    GitExportPlan {
        remote: remote.clone(),
        branch: branch.clone(),
        snapshot_id: snapshot.id.as_str().to_string(),
        included_paths: manifest.included_paths.clone(),
        omitted_paths: manifest
            .omitted_paths
            .iter()
            .chain(manifest.blocked_paths.iter())
            .cloned()
            .collect(),
        signed: false,
        lfs_compatible: false,
        metadata: GitExportMetadata {
            author: None,
            tags: Vec::new(),
            lfs_pointers: Vec::new(),
            modes: git_modes(snapshot),
            symlinks: git_symlinks(snapshot),
            submodules: git_submodules(snapshot),
            signature: None,
        },
        commands: vec![
            GitCommandPlan {
                program: "git".to_string(),
                args: vec!["checkout".to_string(), "-B".to_string(), branch.clone()],
                cwd: None,
            },
            GitCommandPlan {
                program: "git".to_string(),
                args: vec!["add".to_string(), ".".to_string()],
                cwd: None,
            },
            GitCommandPlan {
                program: "git".to_string(),
                args: vec![
                    "commit".to_string(),
                    "-m".to_string(),
                    format!("Export Nebula snapshot {}", snapshot.id),
                ],
                cwd: None,
            },
            GitCommandPlan {
                program: "git".to_string(),
                args: vec!["push".to_string(), remote, branch],
                cwd: None,
            },
        ],
    }
}

pub fn plan_github_pr(proposal: &Proposal, branch: impl Into<String>) -> GitHubPrPlan {
    GitHubPrPlan {
        proposal_id: proposal.id.as_str().to_string(),
        branch: branch.into(),
        title: proposal.title.clone(),
        body: format!(
            "Nebula proposal {} exported from Galaxy {}.",
            proposal.id, proposal.repository_id
        ),
    }
}

pub fn execute_git_export_plan(
    plan: &GitExportPlan,
    worktree: impl AsRef<Path>,
) -> Result<GitExecutionResult, GitProjectionError> {
    let worktree = worktree.as_ref().to_path_buf();
    let commands = plan
        .commands
        .iter()
        .cloned()
        .map(|mut command| {
            command.cwd = Some(worktree.clone());
            command
        })
        .collect::<Vec<_>>();
    execute_git_commands(&commands)
}

pub fn execute_git_commands(
    commands: &[GitCommandPlan],
) -> Result<GitExecutionResult, GitProjectionError> {
    let mut outputs = Vec::new();
    for command in commands {
        let mut process = Command::new(&command.program);
        process.args(&command.args);
        if let Some(cwd) = &command.cwd {
            process.current_dir(cwd);
        }
        let output = process.output().map_err(io_error)?;
        let command_output = GitCommandOutput {
            program: command.program.clone(),
            args: command.args.clone(),
            status_code: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        };
        if !output.status.success() {
            return Err(GitProjectionError::Io {
                message: format!(
                    "git command failed: {} {}: {}",
                    command.program,
                    command.args.join(" "),
                    command_output.stderr
                ),
            });
        }
        outputs.push(command_output);
    }
    Ok(GitExecutionResult { commands: outputs })
}

pub fn detect_lfs_pointers(files: &BTreeMap<String, Vec<u8>>) -> Vec<GitLfsPointer> {
    files
        .iter()
        .filter_map(|(path, bytes)| {
            let text = std::str::from_utf8(bytes).ok()?;
            let mut lines = text.lines();
            if lines.next()? != "version https://git-lfs.github.com/spec/v1" {
                return None;
            }
            let oid = lines
                .find_map(|line| line.strip_prefix("oid sha256:"))
                .map(ToString::to_string)?;
            let size_bytes = lines
                .find_map(|line| line.strip_prefix("size "))
                .and_then(|value| value.parse::<u64>().ok())?;
            Some(GitLfsPointer {
                path: path.clone(),
                oid_sha256: oid,
                size_bytes,
            })
        })
        .collect()
}

pub fn git_modes(snapshot: &TreeSnapshot) -> Vec<GitModeMetadata> {
    snapshot
        .entries
        .iter()
        .filter_map(|entry| match entry.kind {
            TreeEntryKind::Executable => Some(GitModeMetadata {
                path: entry.path.clone(),
                mode: "100755".to_string(),
            }),
            TreeEntryKind::File => Some(GitModeMetadata {
                path: entry.path.clone(),
                mode: "100644".to_string(),
            }),
            TreeEntryKind::Symlink => Some(GitModeMetadata {
                path: entry.path.clone(),
                mode: "120000".to_string(),
            }),
            TreeEntryKind::Directory => None,
        })
        .collect()
}

pub fn git_symlinks(snapshot: &TreeSnapshot) -> Vec<String> {
    snapshot
        .entries
        .iter()
        .filter(|entry| matches!(entry.kind, TreeEntryKind::Symlink))
        .map(|entry| entry.path.clone())
        .collect()
}

pub fn git_submodules(snapshot: &TreeSnapshot) -> Vec<String> {
    snapshot
        .entries
        .iter()
        .filter(|entry| entry.path.ends_with(".gitmodules"))
        .map(|entry| entry.path.clone())
        .collect()
}

pub fn sign_export_manifest(
    snapshot: &TreeSnapshot,
    manifest: &ProjectionManifest,
) -> GitExportSignature {
    GitExportSignature {
        signer: "nebula-oss".to_string(),
        algorithm: "metadata-sha256".to_string(),
        payload_digest: format!(
            "{}:{}:{}:{}",
            snapshot.id,
            manifest.projection_id,
            manifest.included_paths.join(","),
            manifest.blocked_paths.join(",")
        ),
    }
}

fn projection_actions(
    snapshot: &TreeSnapshot,
    decisions: &BTreeMap<String, PolicyDecision>,
) -> Result<Vec<GitProjectionAction>, GitProjectionError> {
    snapshot
        .entries
        .iter()
        .filter(|entry| !matches!(entry.kind, TreeEntryKind::Directory))
        .map(|entry| {
            let decision = decisions.get(&entry.path).ok_or_else(|| {
                GitProjectionError::MissingPolicyDecision {
                    path: entry.path.clone(),
                }
            })?;
            Ok(action_from_decision(entry.path.clone(), decision.clone()))
        })
        .collect()
}

fn action_from_decision(path: String, decision: PolicyDecision) -> GitProjectionAction {
    match decision {
        PolicyDecision::Allow => GitProjectionAction::Include { path },
        PolicyDecision::Redact => GitProjectionAction::Redact {
            path,
            replacement_path: None,
        },
        PolicyDecision::Template => GitProjectionAction::Template {
            template_path: format!("{path}.example"),
            path,
        },
        PolicyDecision::Omit => GitProjectionAction::Omit { path },
        PolicyDecision::Block => GitProjectionAction::Block {
            path,
            reason: "policy blocks Git export".to_string(),
        },
        PolicyDecision::Embargo { until_unix_ms } => GitProjectionAction::Block {
            path,
            reason: format!("embargoed until {until_unix_ms}"),
        },
    }
}

fn manifest_from_actions(
    projection: &Projection,
    snapshot: &TreeSnapshot,
    actions: &[GitProjectionAction],
) -> ProjectionManifest {
    let mut manifest = ProjectionManifest {
        projection_id: projection.id.clone(),
        snapshot_id: projection.snapshot_id.clone(),
        included_tree_roots: Vec::new(),
        included_paths: Vec::new(),
        redacted_paths: Vec::new(),
        templated_paths: Vec::new(),
        omitted_paths: Vec::new(),
        blocked_paths: Vec::new(),
    };

    for action in actions {
        match action {
            GitProjectionAction::Include { path } => manifest.included_paths.push(path.clone()),
            GitProjectionAction::Redact { path, .. } => manifest.redacted_paths.push(path.clone()),
            GitProjectionAction::Template { path, .. } => {
                manifest.templated_paths.push(path.clone())
            }
            GitProjectionAction::Omit { path } => manifest.omitted_paths.push(path.clone()),
            GitProjectionAction::Block { path, .. } => manifest.blocked_paths.push(path.clone()),
        }
    }

    if !actions.is_empty()
        && actions
            .iter()
            .all(|action| matches!(action, GitProjectionAction::Include { .. }))
    {
        manifest
            .included_tree_roots
            .push(snapshot.root_tree_id.clone());
    }

    manifest
}

pub fn draft_git_export(
    proposal: &Proposal,
    projection: &Projection,
    remote_name: impl Into<String>,
    branch_name: impl Into<String>,
) -> GitExport {
    GitExport {
        id: GitExportId::generated(),
        proposal_id: proposal.id.clone(),
        projection_id: projection.id.clone(),
        remote_name: remote_name.into(),
        branch_name: branch_name.into(),
        commit_sha: None,
        pull_request_url: None,
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MaterializedProjection {
    pub root: PathBuf,
    pub written_paths: Vec<String>,
    pub omitted_paths: Vec<String>,
}

pub fn materialize_projection(
    plan: &GitProjectionPlan,
    snapshot: &TreeSnapshot,
    blob_bytes: &BTreeMap<ContentHash, Vec<u8>>,
    output_root: impl AsRef<Path>,
) -> Result<MaterializedProjection, GitProjectionError> {
    if plan.has_blockers() {
        return Err(GitProjectionError::BlockedProjection {
            paths: plan.manifest.blocked_paths.clone(),
        });
    }

    let output_root = output_root.as_ref().to_path_buf();
    fs::create_dir_all(&output_root).map_err(io_error)?;
    let entries_by_path = snapshot
        .entries
        .iter()
        .map(|entry| (entry.path.as_str(), entry))
        .collect::<BTreeMap<_, _>>();
    let mut written_paths = Vec::new();
    let mut omitted_paths = Vec::new();

    for action in &plan.actions {
        match action {
            GitProjectionAction::Include { path } => {
                let Some(entry) = entries_by_path.get(path.as_str()) else {
                    continue;
                };
                let Some(hash) = &entry.hash else {
                    continue;
                };
                let Some(bytes) = blob_bytes.get(hash) else {
                    return Err(GitProjectionError::MissingBlob {
                        path: path.clone(),
                        hash: hash.clone(),
                    });
                };
                write_projection_entry(&output_root, path, &entry.kind, bytes)?;
                written_paths.push(path.clone());
            }
            GitProjectionAction::Redact {
                path,
                replacement_path,
            } => {
                let output_path = replacement_path.as_deref().unwrap_or(path);
                write_projection_file(
                    &output_root,
                    output_path,
                    format!("redacted by Nebula projection policy for {path}\n").as_bytes(),
                )?;
                written_paths.push(output_path.to_string());
            }
            GitProjectionAction::Template {
                path,
                template_path,
            } => {
                write_projection_file(
                    &output_root,
                    template_path,
                    format!("template generated by Nebula for {path}\n").as_bytes(),
                )?;
                written_paths.push(template_path.clone());
            }
            GitProjectionAction::Omit { path } => omitted_paths.push(path.clone()),
            GitProjectionAction::Block { .. } => unreachable!("blockers are rejected above"),
        }
    }

    Ok(MaterializedProjection {
        root: output_root,
        written_paths,
        omitted_paths,
    })
}

fn write_projection_file(
    root: &Path,
    repo_path: &str,
    bytes: &[u8],
) -> Result<(), GitProjectionError> {
    if repo_path.starts_with('/') || repo_path.split('/').any(|part| part == "..") {
        return Err(GitProjectionError::UnsafePath {
            path: repo_path.to_string(),
        });
    }
    let output_path = root.join(repo_path);
    if !output_path.starts_with(root) {
        return Err(GitProjectionError::UnsafePath {
            path: repo_path.to_string(),
        });
    }
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent).map_err(io_error)?;
    }
    fs::write(output_path, bytes).map_err(io_error)
}

fn write_projection_entry(
    root: &Path,
    repo_path: &str,
    kind: &TreeEntryKind,
    bytes: &[u8],
) -> Result<(), GitProjectionError> {
    match kind {
        TreeEntryKind::Directory => {
            let output_path = safe_projection_path(root, repo_path)?;
            fs::create_dir_all(output_path).map_err(io_error)
        }
        TreeEntryKind::Symlink => {
            let output_path = safe_projection_path(root, repo_path)?;
            if let Some(parent) = output_path.parent() {
                fs::create_dir_all(parent).map_err(io_error)?;
            }
            #[cfg(unix)]
            {
                let target = std::str::from_utf8(bytes).map_err(|error| {
                    GitProjectionError::InvalidGitObject {
                        message: format!("symlink target is not UTF-8: {error}"),
                    }
                })?;
                if output_path.exists() {
                    fs::remove_file(&output_path).map_err(io_error)?;
                }
                std::os::unix::fs::symlink(target, output_path).map_err(io_error)
            }
            #[cfg(not(unix))]
            {
                fs::write(output_path, bytes).map_err(io_error)
            }
        }
        TreeEntryKind::Executable => {
            write_projection_file(root, repo_path, bytes)?;
            #[cfg(unix)]
            {
                let output_path = safe_projection_path(root, repo_path)?;
                let mut permissions = fs::metadata(&output_path).map_err(io_error)?.permissions();
                permissions.set_mode(0o755);
                fs::set_permissions(output_path, permissions).map_err(io_error)?;
            }
            Ok(())
        }
        TreeEntryKind::File => write_projection_file(root, repo_path, bytes),
    }
}

fn safe_projection_path(root: &Path, repo_path: &str) -> Result<PathBuf, GitProjectionError> {
    if repo_path.starts_with('/') || repo_path.split('/').any(|part| part == "..") {
        return Err(GitProjectionError::UnsafePath {
            path: repo_path.to_string(),
        });
    }
    let output_path = root.join(repo_path);
    if !output_path.starts_with(root) {
        return Err(GitProjectionError::UnsafePath {
            path: repo_path.to_string(),
        });
    }
    Ok(output_path)
}

fn io_error(error: std::io::Error) -> GitProjectionError {
    GitProjectionError::Io {
        message: error.to_string(),
    }
}

fn git_lines(repo: &Path, args: &[&str]) -> Result<Vec<String>, GitProjectionError> {
    Ok(String::from_utf8_lossy(&git_bytes(repo, args)?)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(ToString::to_string)
        .collect())
}

fn git_bytes(repo: &Path, args: &[&str]) -> Result<Vec<u8>, GitProjectionError> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .map_err(io_error)?;
    if !output.status.success() {
        return Err(GitProjectionError::Io {
            message: String::from_utf8_lossy(&output.stderr).to_string(),
        });
    }
    Ok(output.stdout)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nebula_core::{
        BlobVisibility, ContentBlob, EnvironmentId, EnvironmentKind, ProposalId, RefId,
        RepositoryId, ReviewState, TreeEntry, TreeEntryKind,
    };

    fn fixture() -> (TreeSnapshot, Proposal, Environment) {
        let repository_id = RepositoryId::generated();
        let public = ContentBlob::from_bytes(b"public", None, BlobVisibility::Public);
        let secret = ContentBlob::from_bytes(b"secret", None, BlobVisibility::Public);
        let snapshot = TreeSnapshot::canonical(
            repository_id.clone(),
            Vec::new(),
            vec![
                TreeEntry::file("src/app.ts", &public, None).unwrap(),
                TreeEntry::file(".env.production", &secret, None).unwrap(),
            ],
            Default::default(),
        )
        .unwrap();
        let proposal = Proposal {
            id: ProposalId::generated(),
            repository_id: repository_id.clone(),
            title: "Export safety".to_string(),
            target_ref_id: RefId::generated(),
            changeset_ids: Vec::new(),
            state: ReviewState::Open,
            policy_checks: Vec::new(),
        };
        let environment = Environment {
            id: EnvironmentId::generated(),
            repository_id,
            name: "production".to_string(),
            kind: EnvironmentKind::Production,
        };
        (snapshot, proposal, environment)
    }

    #[test]
    fn projection_fails_when_any_path_lacks_policy_decision() {
        let (snapshot, proposal, environment) = fixture();
        let result = plan_github_projection(
            &snapshot,
            &proposal,
            Actor::Integration("github".to_string()),
            environment,
            BTreeMap::from([("src/app.ts".to_string(), PolicyDecision::Allow)]),
        );

        assert!(matches!(
            result,
            Err(GitProjectionError::MissingPolicyDecision { path }) if path == ".env.production"
        ));
    }

    #[test]
    fn preview_reports_included_and_blocked_paths() {
        let (snapshot, proposal, environment) = fixture();
        let preview = preview_git_projection(
            &snapshot,
            &proposal,
            GitProjectionRequest {
                actor: Actor::Integration("github".to_string()),
                environment,
                target: ProjectionTarget::GitHub,
                path_decisions: BTreeMap::from([
                    ("src/app.ts".to_string(), PolicyDecision::Allow),
                    (".env.production".to_string(), PolicyDecision::Block),
                ]),
            },
        )
        .unwrap();

        assert!(preview.has_blockers);
        assert_eq!(preview.manifest.included_paths, vec!["src/app.ts"]);
        assert_eq!(preview.manifest.blocked_paths, vec![".env.production"]);
    }

    #[test]
    fn detects_git_lfs_pointer_files() {
        let pointers = detect_lfs_pointers(&BTreeMap::from([(
            "asset.bin".to_string(),
            b"version https://git-lfs.github.com/spec/v1\noid sha256:abc123\nsize 42\n".to_vec(),
        )]));
        assert_eq!(pointers.len(), 1);
        assert_eq!(pointers[0].path, "asset.bin");
        assert_eq!(pointers[0].size_bytes, 42);
    }

    #[test]
    fn git_import_plan_is_explicit_about_mirror_only_support() {
        let plan = plan_git_import("https://example.com/repo.git");

        assert!(!plan.preserves_history);
        assert!(!plan.supports_lfs);
        assert!(
            plan.notes
                .iter()
                .any(|note| note.contains("not production-supported"))
        );
    }

    #[test]
    fn migrates_linear_git_history_into_nebula_snapshots() {
        let repo_path = unique_temp_dir("nebula-git-migrate");
        fs::create_dir_all(&repo_path).unwrap();
        git(&repo_path, &["init"]).unwrap();
        git(&repo_path, &["symbolic-ref", "HEAD", "refs/heads/main"]).unwrap();
        git(&repo_path, &["config", "user.name", "Nebula Test"]).unwrap();
        git(&repo_path, &["config", "user.email", "nebula@example.com"]).unwrap();
        fs::write(repo_path.join("app.txt"), "hello\n").unwrap();
        git(&repo_path, &["add", "app.txt"]).unwrap();
        git(&repo_path, &["commit", "-m", "initial"]).unwrap();
        fs::write(repo_path.join("app.txt"), "hello nebula\n").unwrap();
        git(&repo_path, &["commit", "-am", "update"]).unwrap();

        let output = migrate_git_repository(
            &repo_path,
            GitMigrationOptions {
                repository_id: RepositoryId::generated(),
                ref_namespace: "refs/git-migration".to_string(),
                lfs_strategy: GitLfsStrategy::Pointers,
            },
        )
        .unwrap();
        let verification = verify_git_migration(&output);

        assert!(verification.valid, "{:?}", verification.errors);
        assert_eq!(output.snapshots.len(), 2);
        assert_eq!(output.migration_records.len(), 2);
        assert_eq!(output.refs.len(), 1);
        assert_eq!(output.refs[0].nebula_ref.name, "refs/git-migration/main");
        assert_eq!(output.snapshots[1].parent_snapshot_ids.len(), 1);
        assert!(output.snapshots[1].metadata.contains_key("git_commit_sha"));
        assert_eq!(
            output.migration_records[1].snapshot_id,
            output.snapshots[1].id
        );
        assert!(!output.blobs.is_empty());
    }

    #[test]
    fn git_export_records_modes_and_symlinks() {
        let repository_id = RepositoryId::generated();
        let blob = ContentBlob::from_bytes(b"#!/bin/sh", None, BlobVisibility::Public);
        let mut executable = TreeEntry::file("scripts/run.sh", &blob, None).unwrap();
        executable.kind = TreeEntryKind::Executable;
        let mut symlink = TreeEntry::file("bin/run", &blob, None).unwrap();
        symlink.kind = TreeEntryKind::Symlink;
        let snapshot = TreeSnapshot::canonical(
            repository_id,
            Vec::new(),
            vec![executable, symlink],
            Default::default(),
        )
        .unwrap();

        let modes = git_modes(&snapshot);

        assert!(
            modes
                .iter()
                .any(|mode| mode.path == "scripts/run.sh" && mode.mode == "100755")
        );
        assert_eq!(git_symlinks(&snapshot), vec!["bin/run".to_string()]);
    }

    #[test]
    fn git_export_plan_does_not_claim_unimplemented_signing_or_lfs() {
        let (snapshot, proposal, environment) = fixture();
        let projection = plan_git_projection(
            &snapshot,
            &proposal,
            GitProjectionRequest {
                actor: Actor::Public,
                environment,
                target: ProjectionTarget::GitRemote("origin".to_string()),
                path_decisions: BTreeMap::from([
                    ("src/app.ts".to_string(), PolicyDecision::Allow),
                    (".env.production".to_string(), PolicyDecision::Omit),
                ]),
            },
        )
        .unwrap();
        let plan = plan_git_export(&snapshot, &projection.manifest, "origin", "nebula-export");

        assert!(!plan.signed);
        assert!(!plan.lfs_compatible);
        assert!(plan.metadata.signature.is_none());
    }

    #[test]
    fn materialize_projection_preserves_executable_and_symlink_entries() {
        let repository_id = RepositoryId::generated();
        let executable_bytes = b"#!/bin/sh\n".to_vec();
        let symlink_bytes = b"scripts/run.sh".to_vec();
        let executable_blob =
            ContentBlob::from_bytes(&executable_bytes, None, BlobVisibility::Public);
        let symlink_blob = ContentBlob::from_bytes(&symlink_bytes, None, BlobVisibility::Public);
        let mut executable = TreeEntry::file("scripts/run.sh", &executable_blob, None).unwrap();
        executable.kind = TreeEntryKind::Executable;
        let mut symlink = TreeEntry::file("bin/run", &symlink_blob, None).unwrap();
        symlink.kind = TreeEntryKind::Symlink;
        let snapshot = TreeSnapshot::canonical(
            repository_id.clone(),
            Vec::new(),
            vec![executable, symlink],
            Default::default(),
        )
        .unwrap();
        let proposal = Proposal {
            id: ProposalId::generated(),
            repository_id,
            title: "projection".to_string(),
            target_ref_id: RefId::generated(),
            changeset_ids: Vec::new(),
            state: nebula_core::ReviewState::Open,
            policy_checks: Vec::new(),
        };
        let projection = plan_git_projection(
            &snapshot,
            &proposal,
            GitProjectionRequest {
                actor: Actor::Public,
                environment: Environment {
                    id: EnvironmentId::generated(),
                    repository_id: snapshot.repository_id.clone(),
                    name: "production".to_string(),
                    kind: EnvironmentKind::Production,
                },
                target: ProjectionTarget::GitRemote("origin".to_string()),
                path_decisions: BTreeMap::from([
                    ("scripts/run.sh".to_string(), PolicyDecision::Allow),
                    ("bin/run".to_string(), PolicyDecision::Allow),
                ]),
            },
        )
        .unwrap();
        let output = unique_temp_dir("nebula-git-export-materialize");
        let materialized = materialize_projection(
            &projection,
            &snapshot,
            &BTreeMap::from([
                (executable_blob.hash.clone(), executable_bytes),
                (symlink_blob.hash.clone(), symlink_bytes),
            ]),
            &output,
        )
        .unwrap();

        assert_eq!(materialized.written_paths.len(), 2);
        #[cfg(unix)]
        {
            assert_eq!(
                fs::metadata(output.join("scripts/run.sh"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o755
            );
            assert_eq!(
                fs::read_link(output.join("bin/run")).unwrap(),
                PathBuf::from("scripts/run.sh")
            );
        }
    }

    #[test]
    fn migrates_same_tree_git_commits_to_distinct_snapshots() {
        let repo_path = unique_temp_dir("nebula-git-same-tree");
        fs::create_dir_all(&repo_path).unwrap();
        git(&repo_path, &["init"]).unwrap();
        git(&repo_path, &["symbolic-ref", "HEAD", "refs/heads/main"]).unwrap();
        git(&repo_path, &["config", "user.name", "Nebula Test"]).unwrap();
        git(&repo_path, &["config", "user.email", "nebula@example.com"]).unwrap();
        fs::write(repo_path.join("app.txt"), "hello\n").unwrap();
        git(&repo_path, &["add", "app.txt"]).unwrap();
        git(&repo_path, &["commit", "-m", "initial"]).unwrap();
        git(&repo_path, &["commit", "--allow-empty", "-m", "empty"]).unwrap();

        let output = migrate_git_repository(
            &repo_path,
            GitMigrationOptions {
                repository_id: RepositoryId::generated(),
                ref_namespace: "refs/git-migration".to_string(),
                lfs_strategy: GitLfsStrategy::Pointers,
            },
        )
        .unwrap();

        assert_eq!(output.snapshots.len(), 2);
        assert_ne!(output.snapshots[0].id, output.snapshots[1].id);
        assert_eq!(output.snapshots[0].root_hash, output.snapshots[1].root_hash);
    }

    fn unique_temp_dir(prefix: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "{}-{}",
            prefix,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    fn git(repo: &Path, args: &[&str]) -> Result<(), GitProjectionError> {
        git_bytes(repo, args).map(|_| ())
    }
}
