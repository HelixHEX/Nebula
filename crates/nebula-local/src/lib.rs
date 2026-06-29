use anyhow::{Context, Result, bail};
use nebula_core::{
    Actor, BlobId, BlobVisibility, ChangeOperation, ChangeOperationKind, ChangeSet, ChangeSetId,
    ContentBlob, ContentHash, Environment, EnvironmentId, EnvironmentKind, GitMigrationRecord,
    IntegrationActor, MAX_IN_MEMORY_BLOB_BYTES, Operation, OperationKind, OperationView,
    PolicyAction, PolicyDecision, PolicyEngine, PolicyObject, PolicyRequest, PolicyRule, Proposal,
    ProposalId, Ref, RefId, RefTarget, RepositoryId, ReviewState, SecretFileRef, SecretFileRefId,
    TreeDiff, TreeDiffKind, TreeEntry, TreeEntryKind, TreeSnapshot, TreeSnapshotId,
    VisibilityPolicy, WorkspaceId, diff_entries, normalize_repo_path, plan_three_way_merge,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

const NEBULA_DIR: &str = ".nebula";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LocalConfig {
    pub repository_id: RepositoryId,
    pub default_ref: String,
    #[serde(default)]
    pub remotes: BTreeMap<String, LocalRemote>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LocalRemote {
    pub name: String,
    pub url: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LocalWorkspace {
    pub id: WorkspaceId,
    pub name: String,
    pub base_snapshot_id: TreeSnapshotId,
    pub last_snapshot_id: Option<TreeSnapshotId>,
    pub last_changeset_id: Option<ChangeSetId>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LocalStatus {
    pub workspace: LocalWorkspace,
    pub diff: TreeDiff,
    pub catalog: LocalWorkspaceCatalog,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SaveResult {
    pub snapshot: TreeSnapshot,
    pub changeset: ChangeSet,
    pub diff: TreeDiff,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProposalResult {
    pub proposal: Proposal,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MergeResult {
    pub proposal: Proposal,
    pub target_ref: Ref,
    pub merged_snapshot_id: TreeSnapshotId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LocalWorkspaceCatalog {
    pub workspace_id: WorkspaceId,
    pub materialized_paths: BTreeSet<String>,
    pub dirty_paths: BTreeSet<String>,
    #[serde(default)]
    pub indexed_paths: BTreeMap<String, ContentHash>,
    #[serde(default)]
    pub cached_blob_paths: BTreeSet<String>,
    pub last_scan_unix_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LazyHydrationPlan {
    pub snapshot_id: TreeSnapshotId,
    pub missing_paths: Vec<String>,
    pub blob_hashes: Vec<ContentHash>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CacheGcPlan {
    pub keep_blob_paths: BTreeSet<String>,
    pub remove_blob_paths: BTreeSet<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LocalSyncBundle {
    pub repository_id: RepositoryId,
    pub default_ref: String,
    pub refs: Vec<Ref>,
    pub snapshots: Vec<TreeSnapshot>,
    pub changesets: Vec<ChangeSet>,
    pub proposals: Vec<Proposal>,
    pub operations: Vec<Operation>,
    #[serde(default)]
    pub git_migration_records: Vec<GitMigrationRecord>,
    pub blobs: Vec<LocalBlobRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LocalBlobRecord {
    pub blob: ContentBlob,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct LocalRepo {
    root: PathBuf,
    nebula_dir: PathBuf,
}

impl LocalRepo {
    pub fn init(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        let nebula_dir = root.join(NEBULA_DIR);
        if nebula_dir.exists() {
            bail!(
                "Nebula repository already exists at {}",
                nebula_dir.display()
            );
        }

        let repo = Self { root, nebula_dir };
        repo.create_layout()?;

        let repository_id = RepositoryId::generated();
        let empty = TreeSnapshot::canonical(
            repository_id.clone(),
            Vec::new(),
            Vec::new(),
            BTreeMap::new(),
        )?;
        repo.write_snapshot(&empty)?;

        let main_ref = Ref {
            id: RefId::generated(),
            repository_id: repository_id.clone(),
            name: "main".to_string(),
            target: RefTarget::Snapshot(empty.id.clone()),
            policy_id: None,
        };
        repo.write_refs(&BTreeMap::from([("main".to_string(), main_ref)]))?;

        let workspace = LocalWorkspace {
            id: WorkspaceId::generated(),
            name: "main".to_string(),
            base_snapshot_id: empty.id.clone(),
            last_snapshot_id: Some(empty.id.clone()),
            last_changeset_id: None,
        };
        repo.write_workspace(&workspace)?;
        repo.write_catalog(&empty_catalog(workspace.id.clone()))?;
        repo.write_active_workspace(&workspace.name)?;
        repo.write_json(
            &repo.nebula_dir.join("config.json"),
            &LocalConfig {
                repository_id,
                default_ref: "main".to_string(),
                remotes: BTreeMap::new(),
            },
        )?;
        repo.record_operation(
            OperationKind::InitRepository,
            OperationView {
                snapshot_ids: vec![empty.id],
                ref_ids: Vec::new(),
                workspace_ids: vec![workspace.id],
                changeset_ids: Vec::new(),
                proposal_ids: Vec::new(),
                policy_ids: Vec::new(),
            },
        )?;

        Ok(repo)
    }

    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        let nebula_dir = root.join(NEBULA_DIR);
        if !nebula_dir.exists() {
            bail!("Not a Nebula repository. Run `neb init` first.");
        }
        let repo = Self { root, nebula_dir };
        repo.recover_incomplete_writes()?;
        Ok(repo)
    }

    pub fn clone_from_bundle(root: impl AsRef<Path>, remote: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        let remote = remote.as_ref();
        let bundle: LocalSyncBundle = read_json_from_path(remote)?;
        Self::clone_from_bundle_data(root, remote.display().to_string(), &bundle)
    }

    pub fn clone_from_bundle_data(
        root: impl AsRef<Path>,
        remote_url: String,
        bundle: &LocalSyncBundle,
    ) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        if root.join(NEBULA_DIR).exists() {
            bail!(
                "Nebula repository already exists at {}",
                root.join(NEBULA_DIR).display()
            );
        }
        fs::create_dir_all(&root)?;
        let repo = Self {
            nebula_dir: root.join(NEBULA_DIR),
            root,
        };
        repo.create_layout()?;
        repo.import_bundle(bundle)?;
        repo.write_json(
            &repo.nebula_dir.join("config.json"),
            &LocalConfig {
                repository_id: bundle.repository_id.clone(),
                default_ref: bundle.default_ref.clone(),
                remotes: BTreeMap::from([(
                    "origin".to_string(),
                    LocalRemote {
                        name: "origin".to_string(),
                        url: remote_url,
                    },
                )]),
            },
        )?;
        repo.write_active_workspace("main")?;
        let mut materialize_snapshot_id = None;
        if repo.list_workspaces()?.is_empty() {
            let main = repo.ref_by_name(&bundle.default_ref)?;
            let snapshot_id = match main.target {
                RefTarget::Snapshot(id) => id,
                RefTarget::ChangeSet(id) => repo.changeset(&id)?.next_snapshot_id,
                RefTarget::Proposal(id) => {
                    let proposal = repo.proposal(&id)?;
                    let Some(changeset_id) = proposal.changeset_ids.last() else {
                        bail!("origin proposal ref has no changesets");
                    };
                    repo.changeset(changeset_id)?.next_snapshot_id
                }
            };
            materialize_snapshot_id = Some(snapshot_id.clone());
            let workspace = LocalWorkspace {
                id: WorkspaceId::generated(),
                name: "main".to_string(),
                base_snapshot_id: snapshot_id.clone(),
                last_snapshot_id: Some(snapshot_id),
                last_changeset_id: None,
            };
            repo.write_workspace(&workspace)?;
            repo.write_catalog(&empty_catalog(workspace.id.clone()))?;
        }
        if let Some(snapshot_id) = materialize_snapshot_id {
            let snapshot = repo.snapshot(&snapshot_id)?;
            repo.materialize_snapshot(&snapshot)?;
        }
        Ok(repo)
    }

    pub fn status(&self) -> Result<LocalStatus> {
        let workspace = self.active_workspace()?;
        let base = self.snapshot(
            workspace
                .last_snapshot_id
                .as_ref()
                .unwrap_or(&workspace.base_snapshot_id),
        )?;
        let catalog = self
            .read_catalog(&workspace)
            .unwrap_or_else(|_| empty_catalog(workspace.id.clone()));
        let current = self.scan_workspace_overlay(&base, &catalog, false)?;
        let diff = diff_entries(&base.entries, &current.entries)?;
        let catalog = self.catalog_from_diff(&workspace, &current, &diff);
        self.write_catalog(&catalog)?;
        Ok(LocalStatus {
            workspace,
            diff,
            catalog,
        })
    }

    pub fn save(&self, message: Option<String>) -> Result<SaveResult> {
        let mut workspace = self.active_workspace()?;
        let base_snapshot_id = workspace
            .last_snapshot_id
            .clone()
            .unwrap_or_else(|| workspace.base_snapshot_id.clone());
        let base = self.snapshot(&base_snapshot_id)?;
        let catalog = self
            .read_catalog(&workspace)
            .unwrap_or_else(|_| empty_catalog(workspace.id.clone()));
        let current = self.scan_workspace_overlay(&base, &catalog, true)?;
        self.write_snapshot(&current)?;
        let diff = diff_entries(&base.entries, &current.entries)?;
        let changeset = self.create_changeset(&workspace, &base, &current, &diff, message)?;
        self.write_changeset(&changeset)?;
        let catalog = self.catalog_from_diff(&workspace, &current, &diff);
        self.write_catalog(&catalog)?;
        workspace.last_snapshot_id = Some(current.id.clone());
        workspace.last_changeset_id = Some(changeset.id.clone());
        self.write_workspace(&workspace)?;
        let mut refs = self.refs()?;
        if let Some(reference) = refs.get_mut(&workspace.name) {
            reference.target = RefTarget::Snapshot(current.id.clone());
        }
        self.write_refs(&refs)?;
        self.write_catalog(&empty_catalog(workspace.id.clone()))?;
        self.record_operation(
            OperationKind::SaveWorkspace,
            OperationView {
                snapshot_ids: vec![current.id.clone()],
                workspace_ids: vec![workspace.id.clone()],
                changeset_ids: vec![changeset.id.clone()],
                ..OperationView::default()
            },
        )?;

        Ok(SaveResult {
            snapshot: current,
            changeset,
            diff,
        })
    }

    pub fn diff(&self) -> Result<TreeDiff> {
        Ok(self.status()?.diff)
    }

    pub fn active_snapshot(&self) -> Result<TreeSnapshot> {
        let workspace = self.active_workspace()?;
        let snapshot_id = workspace
            .last_snapshot_id
            .as_ref()
            .unwrap_or(&workspace.base_snapshot_id);
        self.snapshot(snapshot_id)
    }

    pub fn blob_bytes_for_snapshot(
        &self,
        snapshot: &TreeSnapshot,
    ) -> Result<BTreeMap<nebula_core::ContentHash, Vec<u8>>> {
        let mut blobs = BTreeMap::new();
        for entry in &snapshot.entries {
            let Some(hash) = &entry.hash else {
                continue;
            };
            let path = self.nebula_dir.join("objects").join(hash.object_path());
            if path.exists() {
                let size_bytes = fs::metadata(&path)?.len();
                if size_bytes > MAX_IN_MEMORY_BLOB_BYTES {
                    bail!(
                        "snapshot blob {}:{} is {} bytes, above the in-memory projection limit of {} bytes",
                        hash.algorithm,
                        hash.digest,
                        size_bytes,
                        MAX_IN_MEMORY_BLOB_BYTES
                    );
                }
                blobs.insert(hash.clone(), fs::read(path)?);
            }
        }
        Ok(blobs)
    }

    pub fn create_workspace(&self, name: String, from_ref: String) -> Result<LocalWorkspace> {
        let refs = self.refs()?;
        let Some(reference) = refs.get(&from_ref) else {
            bail!("Unknown ref `{from_ref}`");
        };
        let snapshot_id = match &reference.target {
            RefTarget::Snapshot(id) => id.clone(),
            RefTarget::ChangeSet(id) => self.changeset(id)?.next_snapshot_id,
            RefTarget::Proposal(id) => {
                let proposal = self.proposal(id)?;
                let Some(changeset_id) = proposal.changeset_ids.last() else {
                    bail!("Proposal `{id}` has no changesets");
                };
                self.changeset(changeset_id)?.next_snapshot_id
            }
        };
        let workspace = LocalWorkspace {
            id: WorkspaceId::generated(),
            name,
            base_snapshot_id: snapshot_id.clone(),
            last_snapshot_id: Some(snapshot_id),
            last_changeset_id: None,
        };
        self.write_workspace(&workspace)?;
        self.record_operation(
            OperationKind::CreateWorkspace,
            OperationView {
                workspace_ids: vec![workspace.id.clone()],
                snapshot_ids: vec![workspace.base_snapshot_id.clone()],
                ..OperationView::default()
            },
        )?;
        Ok(workspace)
    }

    pub fn list_workspaces(&self) -> Result<Vec<LocalWorkspace>> {
        let mut workspaces = Vec::new();
        for entry in fs::read_dir(self.nebula_dir.join("workspaces"))? {
            let entry = entry?;
            if entry.file_name() == "active" {
                continue;
            }
            if entry
                .file_name()
                .to_string_lossy()
                .ends_with(".catalog.json")
            {
                continue;
            }
            if entry.path().extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            workspaces.push(self.read_json(&entry.path())?);
        }
        workspaces.sort_by(|a: &LocalWorkspace, b| a.name.cmp(&b.name));
        Ok(workspaces)
    }

    pub fn switch_workspace(&self, name: &str) -> Result<LocalWorkspace> {
        let previous_workspace = self.active_workspace().ok();
        let previous_catalog = previous_workspace
            .as_ref()
            .and_then(|workspace| self.read_catalog(workspace).ok());
        let workspace = self.workspace_by_name(name)?;
        let snapshot_id = workspace
            .last_snapshot_id
            .as_ref()
            .unwrap_or(&workspace.base_snapshot_id);
        let snapshot = self.snapshot(snapshot_id)?;
        if let Some(catalog) = previous_catalog {
            self.remove_stale_materialized_paths(&catalog, &snapshot)?;
        }
        self.write_active_workspace(&workspace.name)?;
        self.materialize_snapshot(&snapshot)?;
        self.record_operation(
            OperationKind::SwitchWorkspace,
            OperationView {
                workspace_ids: vec![workspace.id.clone()],
                ..OperationView::default()
            },
        )?;
        Ok(workspace)
    }

    pub fn mark_dirty_path(&self, path: String) -> Result<LocalWorkspaceCatalog> {
        let path = normalize_repo_path(&path).map_err(|error| anyhow::anyhow!(error))?;
        let workspace = self.active_workspace()?;
        let mut catalog = self
            .read_catalog(&workspace)
            .unwrap_or_else(|_| empty_catalog(workspace.id.clone()));
        catalog.dirty_paths.insert(path);
        catalog.last_scan_unix_ms = now_unix_ms();
        self.write_catalog(&catalog)?;
        Ok(catalog)
    }

    pub fn lazy_hydration_plan(&self, paths: &[String]) -> Result<LazyHydrationPlan> {
        let workspace = self.active_workspace()?;
        let snapshot_id = workspace
            .last_snapshot_id
            .as_ref()
            .unwrap_or(&workspace.base_snapshot_id)
            .clone();
        let snapshot = self.snapshot(&snapshot_id)?;
        let catalog = self
            .read_catalog(&workspace)
            .unwrap_or_else(|_| empty_catalog(workspace.id.clone()));
        let entries = snapshot
            .entries
            .iter()
            .map(|entry| (entry.path.as_str(), entry))
            .collect::<BTreeMap<_, _>>();
        let mut missing_paths = Vec::new();
        let mut blob_hashes = Vec::new();
        let mut requested_paths = paths
            .iter()
            .map(|path| normalize_repo_path(path).map_err(|error| anyhow::anyhow!(error)))
            .collect::<Result<Vec<_>>>()?;
        requested_paths.sort();
        requested_paths.dedup();
        for path in requested_paths {
            if catalog.materialized_paths.contains(&path) {
                continue;
            }
            let Some(entry) = entries.get(path.as_str()) else {
                continue;
            };
            let Some(hash) = &entry.hash else {
                continue;
            };
            missing_paths.push(path);
            blob_hashes.push(hash.clone());
        }
        blob_hashes.sort_by(|left, right| {
            left.algorithm
                .cmp(&right.algorithm)
                .then_with(|| left.digest.cmp(&right.digest))
        });
        blob_hashes.dedup();
        Ok(LazyHydrationPlan {
            snapshot_id,
            missing_paths,
            blob_hashes,
        })
    }

    pub fn cache_gc_plan(&self) -> Result<CacheGcPlan> {
        let workspace = self.active_workspace()?;
        let catalog = self
            .read_catalog(&workspace)
            .unwrap_or_else(|_| empty_catalog(workspace.id.clone()));
        let snapshot = self.snapshot(
            workspace
                .last_snapshot_id
                .as_ref()
                .unwrap_or(&workspace.base_snapshot_id),
        )?;
        let keep_blob_paths = snapshot
            .entries
            .iter()
            .filter_map(|entry| entry.hash.as_ref().map(ContentHash::object_path))
            .collect::<BTreeSet<_>>();
        let remove_blob_paths = catalog
            .cached_blob_paths
            .difference(&keep_blob_paths)
            .cloned()
            .collect();
        Ok(CacheGcPlan {
            keep_blob_paths,
            remove_blob_paths,
        })
    }

    pub fn propose(&self, target: String, title: String) -> Result<ProposalResult> {
        let workspace = self.active_workspace()?;
        let Some(changeset_id) = workspace.last_changeset_id.clone() else {
            bail!("Active workspace has no saved changeset. Run `neb save` first.");
        };
        let refs = self.refs()?;
        let Some(target_ref) = refs.get(&target) else {
            bail!("Unknown target ref `{target}`");
        };
        let proposal = Proposal {
            id: ProposalId::generated(),
            repository_id: self.config()?.repository_id,
            title,
            target_ref_id: target_ref.id.clone(),
            changeset_ids: vec![changeset_id],
            state: ReviewState::Open,
            policy_checks: Vec::new(),
        };
        self.write_proposal(&proposal)?;
        self.record_operation(
            OperationKind::CreateProposal,
            OperationView {
                proposal_ids: vec![proposal.id.clone()],
                changeset_ids: proposal.changeset_ids.clone(),
                ..OperationView::default()
            },
        )?;
        Ok(ProposalResult { proposal })
    }

    pub fn list_proposals(&self) -> Result<Vec<Proposal>> {
        let mut proposals = Vec::new();
        for entry in fs::read_dir(self.nebula_dir.join("objects/proposals"))? {
            let entry = entry?;
            if entry.path().extension().and_then(|ext| ext.to_str()) == Some("json") {
                proposals.push(self.read_json(&entry.path())?);
            }
        }
        proposals.sort_by(|a: &Proposal, b| a.id.cmp(&b.id));
        Ok(proposals)
    }

    pub fn list_refs(&self) -> Result<Vec<Ref>> {
        let mut refs = self.refs()?.into_values().collect::<Vec<_>>();
        refs.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(refs)
    }

    pub fn add_remote(&self, name: String, url: String) -> Result<LocalRemote> {
        if name.trim().is_empty() {
            bail!("remote name is required");
        }
        if url.trim().is_empty() {
            bail!("remote url is required");
        }
        let mut config = self.config()?;
        let remote = LocalRemote {
            name: name.clone(),
            url,
        };
        config.remotes.insert(name, remote.clone());
        self.write_config(&config)?;
        Ok(remote)
    }

    pub fn remove_remote(&self, name: &str) -> Result<LocalRemote> {
        let mut config = self.config()?;
        let Some(remote) = config.remotes.remove(name) else {
            bail!("unknown remote `{name}`");
        };
        self.write_config(&config)?;
        Ok(remote)
    }

    pub fn list_remotes(&self) -> Result<Vec<LocalRemote>> {
        let mut remotes = self.config()?.remotes.into_values().collect::<Vec<_>>();
        remotes.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(remotes)
    }

    pub fn push(&self, remote_name: Option<String>) -> Result<PathBuf> {
        let remote = self.resolve_remote(remote_name)?;
        let path = remote_path(&remote.url)?;
        let bundle = self.export_bundle()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        self.write_json(&path, &bundle)?;
        Ok(path)
    }

    pub fn pull(&self, remote_name: Option<String>) -> Result<LocalSyncBundle> {
        let remote = self.resolve_remote(remote_name)?;
        let path = remote_path(&remote.url)?;
        let bundle: LocalSyncBundle = self.read_json(&path)?;
        self.import_bundle(&bundle)?;
        Ok(bundle)
    }

    pub fn set_policy(
        &self,
        path_glob: String,
        decision: PolicyDecision,
    ) -> Result<VisibilityPolicy> {
        let config = self.config()?;
        let policy = VisibilityPolicy {
            id: nebula_core::PolicyId::generated(),
            repository_id: config.repository_id,
            name: format!("local policy for {path_glob}"),
            priority: 100,
            rules: vec![PolicyRule {
                actor: Actor::Public,
                environment_id: None,
                environment_kind: None,
                path_glob: Some(path_glob),
                actions: vec![
                    PolicyAction::ReadPath,
                    PolicyAction::ReadBlob,
                    PolicyAction::ExportGit,
                ],
                decision,
                reason: Some("local CLI policy".to_string()),
            }],
        };
        self.write_policy(&policy)?;
        Ok(policy)
    }

    pub fn list_policies(&self) -> Result<Vec<VisibilityPolicy>> {
        let mut policies = self.read_object_dir("objects/policies")?;
        policies.sort_by(|a: &VisibilityPolicy, b| a.name.cmp(&b.name));
        Ok(policies)
    }

    pub fn check_policy(
        &self,
        path: String,
        action: PolicyAction,
    ) -> Result<nebula_core::PolicyEvaluation> {
        let config = self.config()?;
        let engine = PolicyEngine::new(self.list_policies()?);
        Ok(engine.evaluate(&PolicyRequest {
            repository_id: config.repository_id,
            actor: Actor::Public,
            environment: None,
            action,
            object: PolicyObject::Path(path.clone()),
            path: Some(path),
        }))
    }

    pub fn create_environment(&self, name: String) -> Result<Environment> {
        let config = self.config()?;
        let kind = match name.as_str() {
            "development" => EnvironmentKind::Development,
            "staging" => EnvironmentKind::Staging,
            "production" => EnvironmentKind::Production,
            _ => EnvironmentKind::Custom(name.clone()),
        };
        let environment = Environment {
            id: EnvironmentId::new(format!("env_local_{name}")),
            repository_id: config.repository_id,
            name,
            kind,
        };
        self.write_json(&self.environment_path(&environment.id), &environment)?;
        Ok(environment)
    }

    pub fn list_environments(&self) -> Result<Vec<Environment>> {
        let mut environments = self.read_object_dir("objects/environments")?;
        environments.sort_by(|a: &Environment, b| a.name.cmp(&b.name));
        Ok(environments)
    }

    pub fn add_integration(&self, provider: String) -> Result<IntegrationActor> {
        let integration = IntegrationActor {
            actor: Actor::Integration(provider.clone()),
            provider: provider.clone(),
            display_name: provider,
        };
        self.write_json(&self.integration_path(&integration.provider), &integration)?;
        Ok(integration)
    }

    pub fn list_integrations(&self) -> Result<Vec<IntegrationActor>> {
        let mut integrations = self.read_object_dir("objects/integrations")?;
        integrations.sort_by(|a: &IntegrationActor, b| a.provider.cmp(&b.provider));
        Ok(integrations)
    }

    pub fn add_secret(&self, name: String) -> Result<SecretFileRef> {
        let config = self.config()?;
        let secret = SecretFileRef {
            id: SecretFileRefId::generated(),
            repository_id: config.repository_id,
            name,
            environment_id: None,
            blob_id: None,
            key_envelope_id: None,
        };
        self.write_json(&self.secret_path(&secret.id), &secret)?;
        Ok(secret)
    }

    pub fn list_secrets(&self) -> Result<Vec<SecretFileRef>> {
        let mut secrets = self.read_object_dir("objects/secrets")?;
        secrets.sort_by(|a: &SecretFileRef, b| a.name.cmp(&b.name));
        Ok(secrets)
    }

    pub fn ref_by_name(&self, name: &str) -> Result<Ref> {
        self.refs()?
            .get(name)
            .cloned()
            .with_context(|| format!("unknown ref `{name}`"))
    }

    pub fn proposal_by_string(&self, raw: &str) -> Result<Proposal> {
        self.proposal(&ProposalId::new(raw.to_string()))
    }

    pub fn close_proposal(&self, raw: &str) -> Result<Proposal> {
        let mut proposal = self.proposal_by_string(raw)?;
        match proposal.state {
            ReviewState::Merged => bail!("Proposal `{raw}` is already merged."),
            ReviewState::Closed => Ok(proposal),
            _ => {
                proposal.state = ReviewState::Closed;
                self.write_proposal(&proposal)?;
                self.record_operation(
                    OperationKind::UpdateProposal,
                    OperationView {
                        proposal_ids: vec![proposal.id.clone()],
                        ..OperationView::default()
                    },
                )?;
                Ok(proposal)
            }
        }
    }

    pub fn merge_proposal(&self, raw: &str) -> Result<MergeResult> {
        let mut proposal = self.proposal_by_string(raw)?;
        match proposal.state {
            ReviewState::Open | ReviewState::Approved => {}
            ReviewState::Blocked => bail!("Proposal `{raw}` is blocked."),
            ReviewState::Merged => bail!("Proposal `{raw}` is already merged."),
            ReviewState::Closed => bail!("Proposal `{raw}` is closed."),
        }

        let Some(changeset_id) = proposal.changeset_ids.last() else {
            bail!("Proposal `{raw}` has no changesets.");
        };
        let changeset = self.changeset(changeset_id)?;
        let mut refs = self.refs()?;
        let Some((target_name, mut target_ref)) = refs
            .iter()
            .find(|(_, reference)| reference.id == proposal.target_ref_id)
            .map(|(name, reference)| (name.clone(), reference.clone()))
        else {
            bail!("Proposal `{raw}` points to an unknown target ref.");
        };

        let target_snapshot_id = match &target_ref.target {
            RefTarget::Snapshot(id) => id.clone(),
            RefTarget::ChangeSet(id) => self.changeset(id)?.next_snapshot_id,
            RefTarget::Proposal(id) => {
                let target_proposal = self.proposal(id)?;
                let Some(target_changeset_id) = target_proposal.changeset_ids.last() else {
                    bail!("Target proposal `{id}` has no changesets.");
                };
                self.changeset(target_changeset_id)?.next_snapshot_id
            }
        };

        let base_snapshot = self.snapshot(&changeset.base_snapshot_id)?;
        let target_snapshot = self.snapshot(&target_snapshot_id)?;
        let proposed_snapshot = self.snapshot(&changeset.next_snapshot_id)?;
        let merge_plan = plan_three_way_merge(
            &target_snapshot_id,
            &changeset,
            &base_snapshot,
            &target_snapshot,
            &proposed_snapshot,
        );
        if !merge_plan.conflicts.is_empty() {
            let conflicts = merge_plan
                .conflicts
                .iter()
                .map(|conflict| format!("{} ({:?})", conflict.path, conflict.kind))
                .collect::<Vec<_>>()
                .join(", ");
            bail!("Proposal `{raw}` cannot merge into `{target_name}`: {conflicts}");
        }

        let merged_snapshot_id = if let Some(merged_snapshot) = merge_plan.output_snapshot {
            self.write_snapshot(&merged_snapshot)?;
            merged_snapshot.id
        } else {
            changeset.next_snapshot_id.clone()
        };
        target_ref.target = RefTarget::Snapshot(merged_snapshot_id.clone());
        refs.insert(target_name, target_ref.clone());
        self.write_refs(&refs)?;

        proposal.state = ReviewState::Merged;
        self.write_proposal(&proposal)?;
        self.record_operation(
            OperationKind::UpdateRef,
            OperationView {
                ref_ids: vec![target_ref.id.clone()],
                proposal_ids: vec![proposal.id.clone()],
                changeset_ids: vec![changeset.id.clone()],
                snapshot_ids: vec![merged_snapshot_id.clone()],
                ..OperationView::default()
            },
        )?;

        Ok(MergeResult {
            proposal,
            target_ref,
            merged_snapshot_id,
        })
    }

    pub fn proposal(&self, id: &ProposalId) -> Result<Proposal> {
        self.read_json(&self.proposal_path(id))
    }

    fn create_layout(&self) -> Result<()> {
        for path in [
            "objects/blobs",
            "objects/snapshots",
            "objects/changesets",
            "objects/proposals",
            "objects/operations",
            "objects/policies",
            "objects/environments",
            "objects/integrations",
            "objects/secrets",
            "workspaces",
        ] {
            fs::create_dir_all(self.nebula_dir.join(path))?;
        }
        Ok(())
    }

    fn recover_incomplete_writes(&self) -> Result<()> {
        remove_atomic_write_temps(&self.root)?;
        remove_atomic_write_temps(&self.nebula_dir)?;
        Ok(())
    }

    #[allow(dead_code)]
    fn scan_working_tree(&self, persist_blobs: bool) -> Result<TreeSnapshot> {
        let config = self.config()?;
        let mut entries = Vec::new();
        self.scan_dir(&self.root, &mut entries, persist_blobs)?;
        TreeSnapshot::canonical(config.repository_id, Vec::new(), entries, BTreeMap::new())
            .map_err(Into::into)
    }

    fn scan_workspace_overlay(
        &self,
        base: &TreeSnapshot,
        catalog: &LocalWorkspaceCatalog,
        persist_blobs: bool,
    ) -> Result<TreeSnapshot> {
        if catalog.dirty_paths.is_empty() {
            let config = self.config()?;
            let mut entries = Vec::new();
            self.scan_dir(&self.root, &mut entries, persist_blobs)?;
            return TreeSnapshot::canonical(
                config.repository_id,
                vec![base.id.clone()],
                entries,
                BTreeMap::new(),
            )
            .map_err(Into::into);
        }
        let mut entries = base
            .entries
            .iter()
            .map(|entry| (entry.path.clone(), entry.clone()))
            .collect::<BTreeMap<_, _>>();
        entries.retain(|path, _| !should_skip(Path::new(path)));
        for dirty_path in &catalog.dirty_paths {
            let dirty_path =
                normalize_repo_path(dirty_path).map_err(|error| anyhow::anyhow!(error))?;
            if should_skip(Path::new(&dirty_path)) {
                continue;
            }
            let path = self.root.join(&dirty_path);
            ensure_child_path(&self.root, &path)?;
            if !path.exists() {
                entries.remove(&dirty_path);
                continue;
            }
            let metadata = fs::metadata(&path)?;
            if !metadata.is_file() {
                continue;
            }
            let blob = content_blob_from_path(&path)?;
            if persist_blobs {
                self.write_blob_from_path(&blob, &path)?;
            }
            entries.insert(
                dirty_path.clone(),
                TreeEntry::file(dirty_path, &blob, None)?,
            );
        }
        TreeSnapshot::canonical(
            base.repository_id.clone(),
            vec![base.id.clone()],
            entries.into_values().collect(),
            BTreeMap::new(),
        )
        .map_err(Into::into)
    }

    #[allow(dead_code)]
    fn scan_dir(
        &self,
        dir: &Path,
        entries: &mut Vec<TreeEntry>,
        persist_blobs: bool,
    ) -> Result<()> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            let relative = path
                .strip_prefix(&self.root)
                .context("working tree path should be under repo root")?;
            if should_skip(relative) {
                continue;
            }
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.is_dir() {
                entries.push(TreeEntry::directory(path_to_repo_string(relative))?);
                self.scan_dir(&path, entries, persist_blobs)?;
                continue;
            }
            if metadata.file_type().is_symlink() {
                let target = fs::read_link(&path)?;
                let bytes = target.to_string_lossy().as_bytes().to_vec();
                let blob = ContentBlob::from_bytes(&bytes, None, BlobVisibility::Public);
                if persist_blobs {
                    self.write_blob(&blob, &bytes)?;
                }
                entries.push(TreeEntry {
                    path: path_to_repo_string(relative),
                    kind: TreeEntryKind::Symlink,
                    blob_id: Some(blob.id),
                    hash: Some(blob.hash),
                    size_bytes: Some(blob.size_bytes),
                    policy_id: None,
                });
                continue;
            }
            if !metadata.is_file() {
                continue;
            }
            let blob = content_blob_from_path(&path)?;
            if persist_blobs {
                self.write_blob_from_path(&blob, &path)?;
            }
            let kind = if is_executable(&metadata) {
                TreeEntryKind::Executable
            } else {
                TreeEntryKind::File
            };
            entries.push(TreeEntry {
                path: path_to_repo_string(relative),
                kind,
                blob_id: Some(blob.id),
                hash: Some(blob.hash),
                size_bytes: Some(blob.size_bytes),
                policy_id: None,
            });
        }
        Ok(())
    }

    fn create_changeset(
        &self,
        workspace: &LocalWorkspace,
        base: &TreeSnapshot,
        current: &TreeSnapshot,
        diff: &TreeDiff,
        message: Option<String>,
    ) -> Result<ChangeSet> {
        let before = base
            .entries
            .iter()
            .map(|entry| (entry.path.clone(), entry))
            .collect::<BTreeMap<_, _>>();
        let after = current
            .entries
            .iter()
            .map(|entry| (entry.path.clone(), entry))
            .collect::<BTreeMap<_, _>>();
        let operations = diff
            .entries
            .iter()
            .map(|entry| ChangeOperation {
                path: entry.path.clone(),
                kind: match entry.kind {
                    TreeDiffKind::Added => ChangeOperationKind::Add,
                    TreeDiffKind::Modified => ChangeOperationKind::Modify,
                    TreeDiffKind::Deleted => ChangeOperationKind::Delete,
                },
                before_blob_id: before
                    .get(&entry.path)
                    .and_then(|entry| entry.blob_id.clone()),
                after_blob_id: after
                    .get(&entry.path)
                    .and_then(|entry| entry.blob_id.clone()),
                policy_id: after
                    .get(&entry.path)
                    .and_then(|entry| entry.policy_id.clone())
                    .or_else(|| {
                        before
                            .get(&entry.path)
                            .and_then(|entry| entry.policy_id.clone())
                    }),
            })
            .collect();
        let changed_paths = diff
            .entries
            .iter()
            .map(|entry| entry.path.clone())
            .collect();
        Ok(ChangeSet {
            id: ChangeSetId::generated(),
            repository_id: current.repository_id.clone(),
            workspace_id: workspace.id.clone(),
            base_snapshot_id: base.id.clone(),
            next_snapshot_id: current.id.clone(),
            author: Actor::User("local".to_string()),
            summary: message.unwrap_or_else(|| "Local save".to_string()),
            operations,
            changed_paths,
            changed_symbols: Vec::new(),
            changed_packages: Vec::new(),
            affected_targets: Vec::new(),
            affected_tests: Vec::new(),
        })
    }

    pub fn config(&self) -> Result<LocalConfig> {
        self.read_json(&self.nebula_dir.join("config.json"))
    }

    fn write_config(&self, config: &LocalConfig) -> Result<()> {
        self.write_json(&self.nebula_dir.join("config.json"), config)
    }

    fn refs(&self) -> Result<BTreeMap<String, Ref>> {
        self.read_json(&self.nebula_dir.join("refs.json"))
    }

    fn write_refs(&self, refs: &BTreeMap<String, Ref>) -> Result<()> {
        self.write_json(&self.nebula_dir.join("refs.json"), refs)
    }

    fn active_workspace(&self) -> Result<LocalWorkspace> {
        let active = fs::read_to_string(self.nebula_dir.join("workspaces/active"))?;
        self.workspace_by_name(active.trim())
    }

    fn workspace_by_name(&self, name: &str) -> Result<LocalWorkspace> {
        self.read_json(&self.workspace_path(name))
    }

    fn write_active_workspace(&self, name: &str) -> Result<()> {
        atomic_write(self.nebula_dir.join("workspaces/active"), name.as_bytes())?;
        Ok(())
    }

    fn write_workspace(&self, workspace: &LocalWorkspace) -> Result<()> {
        self.write_json(&self.workspace_path(&workspace.name), workspace)
    }

    fn catalog_from_diff(
        &self,
        workspace: &LocalWorkspace,
        snapshot: &TreeSnapshot,
        diff: &TreeDiff,
    ) -> LocalWorkspaceCatalog {
        let indexed_paths = snapshot
            .entries
            .iter()
            .filter_map(|entry| {
                entry
                    .hash
                    .as_ref()
                    .map(|hash| (entry.path.clone(), hash.clone()))
            })
            .collect();
        let cached_blob_paths = snapshot
            .entries
            .iter()
            .filter_map(|entry| entry.hash.as_ref().map(ContentHash::object_path))
            .collect();
        LocalWorkspaceCatalog {
            workspace_id: workspace.id.clone(),
            materialized_paths: snapshot
                .entries
                .iter()
                .map(|entry| entry.path.clone())
                .collect(),
            dirty_paths: diff
                .entries
                .iter()
                .map(|entry| entry.path.clone())
                .collect(),
            indexed_paths,
            cached_blob_paths,
            last_scan_unix_ms: now_unix_ms(),
        }
    }

    fn write_catalog(&self, catalog: &LocalWorkspaceCatalog) -> Result<()> {
        let Some(workspace) = self.list_workspaces().ok().and_then(|workspaces| {
            workspaces
                .into_iter()
                .find(|w| w.id == catalog.workspace_id)
        }) else {
            return Ok(());
        };
        self.write_json(&self.catalog_path(&workspace.name), catalog)
    }

    fn read_catalog(&self, workspace: &LocalWorkspace) -> Result<LocalWorkspaceCatalog> {
        self.read_json(&self.catalog_path(&workspace.name))
    }

    fn remove_stale_materialized_paths(
        &self,
        catalog: &LocalWorkspaceCatalog,
        target_snapshot: &TreeSnapshot,
    ) -> Result<()> {
        let target_paths = target_snapshot
            .entries
            .iter()
            .map(|entry| entry.path.as_str())
            .collect::<BTreeSet<_>>();
        for path in catalog.materialized_paths.iter().rev() {
            if target_paths.contains(path.as_str()) || catalog.dirty_paths.contains(path) {
                continue;
            }
            let output_path = self.root.join(path);
            ensure_child_path(&self.root, &output_path)?;
            if !output_path.exists() && !output_path.is_symlink() {
                continue;
            }
            if output_path.is_dir() && !output_path.is_symlink() {
                if fs::read_dir(&output_path)?.next().is_none() {
                    fs::remove_dir(&output_path)?;
                }
            } else {
                fs::remove_file(&output_path)?;
            }
        }
        Ok(())
    }

    fn materialize_snapshot(&self, snapshot: &TreeSnapshot) -> Result<()> {
        for entry in &snapshot.entries {
            let output_path = self.root.join(&entry.path);
            ensure_child_path(&self.root, &output_path)?;
            if matches!(entry.kind, TreeEntryKind::Directory) {
                fs::create_dir_all(&output_path)?;
                continue;
            }
            let Some(hash) = &entry.hash else {
                continue;
            };
            let blob_path = self.nebula_dir.join("objects").join(hash.object_path());
            if !blob_path.exists() {
                bail!(
                    "missing required blob for `{}` during materialization: {}:{}",
                    entry.path,
                    hash.algorithm,
                    hash.digest
                );
            }
            if output_path.exists() || output_path.is_symlink() {
                if !matches_tree_entry_content(&output_path, &blob_path, entry)? {
                    bail!(
                        "refusing to overwrite local file `{}` during materialization; save or remove it first",
                        entry.path
                    );
                }
                enforce_existing_kind(&output_path, &entry.kind)?;
                continue;
            }
            if let Some(parent) = output_path.parent() {
                fs::create_dir_all(parent)?;
            }
            match entry.kind {
                TreeEntryKind::File => {
                    atomic_copy(blob_path, output_path)?;
                }
                TreeEntryKind::Executable => {
                    atomic_copy(blob_path, &output_path)?;
                    make_executable(&output_path)?;
                }
                TreeEntryKind::Symlink => {
                    let bytes = fs::read(blob_path)?;
                    create_symlink(&output_path, &bytes)?;
                }
                TreeEntryKind::Directory => {}
            }
        }
        Ok(())
    }

    fn snapshot(&self, id: &TreeSnapshotId) -> Result<TreeSnapshot> {
        self.read_json(&self.snapshot_path(id))
    }

    fn write_snapshot(&self, snapshot: &TreeSnapshot) -> Result<()> {
        self.write_json(&self.snapshot_path(&snapshot.id), snapshot)
    }

    fn changeset(&self, id: &ChangeSetId) -> Result<ChangeSet> {
        self.read_json(&self.changeset_path(id))
    }

    fn write_changeset(&self, changeset: &ChangeSet) -> Result<()> {
        self.write_json(&self.changeset_path(&changeset.id), changeset)
    }

    fn write_proposal(&self, proposal: &Proposal) -> Result<()> {
        self.write_json(&self.proposal_path(&proposal.id), proposal)
    }

    fn write_policy(&self, policy: &VisibilityPolicy) -> Result<()> {
        self.write_json(&self.policy_path(&policy.id), policy)
    }

    fn record_operation(&self, kind: OperationKind, output_view: OperationView) -> Result<()> {
        let config = self.config()?;
        let parent_operation_ids =
            fs::read_to_string(self.nebula_dir.join("objects/operations/head"))
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .map(|s| vec![nebula_core::OperationId::new(s)])
                .unwrap_or_default();
        let operation = Operation::new(
            config.repository_id,
            parent_operation_ids,
            Actor::User("local".to_string()),
            now_unix_ms(),
            kind,
            OperationView::default(),
            output_view,
        );
        self.write_json(&self.operation_path(&operation.id), &operation)?;
        atomic_write(
            self.nebula_dir.join("objects/operations/head"),
            operation.id.as_str().as_bytes(),
        )?;
        Ok(())
    }

    fn write_blob(&self, blob: &ContentBlob, bytes: &[u8]) -> Result<()> {
        verify_blob_bytes(blob, bytes)?;
        let path = self
            .nebula_dir
            .join("objects")
            .join(blob.hash.object_path());
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        if !path.exists() {
            atomic_write(path, bytes)?;
        } else {
            verify_blob_path(blob, &path)?;
        }
        Ok(())
    }

    pub fn blob_path(&self, hash: &ContentHash) -> PathBuf {
        self.nebula_dir.join("objects").join(hash.object_path())
    }

    pub fn copy_blob_to_path(
        &self,
        hash: &ContentHash,
        destination: impl AsRef<Path>,
    ) -> Result<u64> {
        let source = self.blob_path(hash);
        if !source.exists() {
            bail!("missing local blob {}:{}", hash.algorithm, hash.digest);
        }
        if let Some(parent) = destination.as_ref().parent() {
            fs::create_dir_all(parent)?;
        }
        let bytes = fs::copy(&source, destination.as_ref())?;
        let (actual_hash, _) = ContentHash::sha256_reader(fs::File::open(destination.as_ref())?)?;
        if &actual_hash != hash {
            bail!(
                "blob checksum mismatch after copy: expected {}:{}, got {}:{}",
                hash.algorithm,
                hash.digest,
                actual_hash.algorithm,
                actual_hash.digest
            );
        }
        Ok(bytes)
    }

    pub fn write_blob_from_path(
        &self,
        blob: &ContentBlob,
        source: impl AsRef<Path>,
    ) -> Result<u64> {
        let (actual_hash, size_bytes) =
            ContentHash::sha256_reader(fs::File::open(source.as_ref())?)?;
        if actual_hash != blob.hash || size_bytes != blob.size_bytes {
            bail!(
                "blob checksum mismatch: expected {}:{} ({} bytes), got {}:{} ({} bytes)",
                blob.hash.algorithm,
                blob.hash.digest,
                blob.size_bytes,
                actual_hash.algorithm,
                actual_hash.digest,
                size_bytes
            );
        }
        let destination = self.blob_path(&blob.hash);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)?;
        }
        if !destination.exists() {
            atomic_copy(source, destination)?;
        }
        Ok(size_bytes)
    }

    pub fn export_bundle(&self) -> Result<LocalSyncBundle> {
        let config = self.config()?;
        let snapshots: Vec<TreeSnapshot> = self.read_object_dir("objects/snapshots")?;
        let changesets: Vec<ChangeSet> = self.read_object_dir("objects/changesets")?;
        let proposals: Vec<Proposal> = self.read_object_dir("objects/proposals")?;
        let operations: Vec<Operation> = self.read_object_dir("objects/operations")?;
        let git_migration_records: Vec<GitMigrationRecord> =
            self.read_object_dir("objects/git-migrations")?;
        let mut blobs = BTreeMap::new();
        for snapshot in &snapshots {
            for entry in &snapshot.entries {
                let Some(hash) = &entry.hash else {
                    continue;
                };
                if blobs.contains_key(hash) {
                    continue;
                }
                let blob = ContentBlob {
                    id: entry
                        .blob_id
                        .clone()
                        .unwrap_or_else(|| nebula_core::BlobId::from_hash(hash)),
                    hash: hash.clone(),
                    size_bytes: entry.size_bytes.unwrap_or_default(),
                    media_type: None,
                    visibility: BlobVisibility::Public,
                };
                if blob.size_bytes > MAX_IN_MEMORY_BLOB_BYTES {
                    bail!(
                        "blob for `{}` is too large for in-memory bundle export ({} bytes > {} bytes); use streaming sync",
                        entry.path,
                        blob.size_bytes,
                        MAX_IN_MEMORY_BLOB_BYTES
                    );
                }
                let path = self.nebula_dir.join("objects").join(hash.object_path());
                if !path.exists() {
                    bail!(
                        "snapshot `{}` references missing blob for `{}`: {}:{}",
                        snapshot.id,
                        entry.path,
                        hash.algorithm,
                        hash.digest
                    );
                }
                let bytes = fs::read(path)?;
                verify_blob_bytes(&blob, &bytes)?;
                blobs.insert(hash.clone(), LocalBlobRecord { blob, bytes });
            }
        }
        Ok(LocalSyncBundle {
            repository_id: config.repository_id,
            default_ref: config.default_ref,
            refs: self.list_refs()?,
            snapshots,
            changesets,
            proposals,
            operations,
            git_migration_records,
            blobs: blobs.into_values().collect(),
        })
    }

    pub fn export_bundle_metadata(&self) -> Result<LocalSyncBundle> {
        let config = self.config()?;
        let snapshots: Vec<TreeSnapshot> = self.read_object_dir("objects/snapshots")?;
        let changesets: Vec<ChangeSet> = self.read_object_dir("objects/changesets")?;
        let proposals: Vec<Proposal> = self.read_object_dir("objects/proposals")?;
        let operations: Vec<Operation> = self.read_object_dir("objects/operations")?;
        let git_migration_records: Vec<GitMigrationRecord> =
            self.read_object_dir("objects/git-migrations")?;
        let mut blobs = BTreeMap::new();
        for snapshot in &snapshots {
            for entry in &snapshot.entries {
                let Some(hash) = &entry.hash else {
                    continue;
                };
                if blobs.contains_key(hash) {
                    continue;
                }
                let blob = ContentBlob {
                    id: entry
                        .blob_id
                        .clone()
                        .unwrap_or_else(|| nebula_core::BlobId::from_hash(hash)),
                    hash: hash.clone(),
                    size_bytes: entry.size_bytes.unwrap_or_default(),
                    media_type: None,
                    visibility: BlobVisibility::Public,
                };
                let path = self.blob_path(hash);
                if !path.exists() {
                    bail!(
                        "snapshot `{}` references missing blob for `{}`: {}:{}",
                        snapshot.id,
                        entry.path,
                        hash.algorithm,
                        hash.digest
                    );
                }
                blobs.insert(
                    hash.clone(),
                    LocalBlobRecord {
                        blob,
                        bytes: Vec::new(),
                    },
                );
            }
        }
        Ok(LocalSyncBundle {
            repository_id: config.repository_id,
            default_ref: config.default_ref,
            refs: self.list_refs()?,
            snapshots,
            changesets,
            proposals,
            operations,
            git_migration_records,
            blobs: blobs.into_values().collect(),
        })
    }

    pub fn import_bundle(&self, bundle: &LocalSyncBundle) -> Result<()> {
        for snapshot in &bundle.snapshots {
            self.write_snapshot(snapshot)?;
        }
        for changeset in &bundle.changesets {
            self.write_changeset(changeset)?;
        }
        for proposal in &bundle.proposals {
            self.write_proposal(proposal)?;
        }
        for operation in &bundle.operations {
            self.write_json(&self.operation_path(&operation.id), operation)?;
        }
        for record in &bundle.git_migration_records {
            self.write_json(
                &self
                    .nebula_dir
                    .join("objects/git-migrations")
                    .join(record.id.as_str()),
                record,
            )?;
        }
        for blob in &bundle.blobs {
            if blob.bytes.is_empty() {
                let path = self.blob_path(&blob.blob.hash);
                if !path.exists() {
                    bail!(
                        "sync bundle is missing bytes for blob {} and no local blob exists",
                        blob.blob.hash.digest
                    );
                }
                let (actual_hash, size_bytes) = ContentHash::sha256_reader(fs::File::open(path)?)?;
                if actual_hash != blob.blob.hash || size_bytes != blob.blob.size_bytes {
                    bail!(
                        "local streamed blob checksum mismatch for {}",
                        blob.blob.hash.digest
                    );
                }
            } else {
                verify_blob_bytes(&blob.blob, &blob.bytes)?;
                self.write_blob(&blob.blob, &blob.bytes)?;
            }
        }
        let mut refs = self.refs().unwrap_or_default();
        for reference in &bundle.refs {
            refs.insert(reference.name.clone(), reference.clone());
        }
        self.write_refs(&refs)
    }

    fn resolve_remote(&self, remote_name: Option<String>) -> Result<LocalRemote> {
        let name = remote_name.unwrap_or_else(|| "origin".to_string());
        self.config()?
            .remotes
            .get(&name)
            .cloned()
            .with_context(|| format!("unknown remote `{name}`"))
    }

    fn read_object_dir<T: for<'de> Deserialize<'de>>(&self, relative: &str) -> Result<Vec<T>> {
        let mut values = Vec::new();
        let dir = self.nebula_dir.join(relative);
        if !dir.exists() {
            return Ok(values);
        }
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            if entry.path().extension().and_then(|ext| ext.to_str()) == Some("json") {
                values.push(self.read_json(&entry.path())?);
            }
        }
        Ok(values)
    }

    fn workspace_path(&self, name: &str) -> PathBuf {
        self.nebula_dir
            .join("workspaces")
            .join(format!("{}.json", safe_name(name)))
    }

    fn catalog_path(&self, name: &str) -> PathBuf {
        self.nebula_dir
            .join("workspaces")
            .join(format!("{}.catalog.json", safe_name(name)))
    }

    fn snapshot_path(&self, id: &TreeSnapshotId) -> PathBuf {
        self.nebula_dir
            .join("objects/snapshots")
            .join(format!("{}.json", safe_name(id.as_str())))
    }

    fn changeset_path(&self, id: &ChangeSetId) -> PathBuf {
        self.nebula_dir
            .join("objects/changesets")
            .join(format!("{}.json", safe_name(id.as_str())))
    }

    fn proposal_path(&self, id: &ProposalId) -> PathBuf {
        self.nebula_dir
            .join("objects/proposals")
            .join(format!("{}.json", safe_name(id.as_str())))
    }

    fn operation_path(&self, id: &nebula_core::OperationId) -> PathBuf {
        self.nebula_dir
            .join("objects/operations")
            .join(format!("{}.json", safe_name(id.as_str())))
    }

    fn policy_path(&self, id: &nebula_core::PolicyId) -> PathBuf {
        self.nebula_dir
            .join("objects/policies")
            .join(format!("{}.json", safe_name(id.as_str())))
    }

    fn environment_path(&self, id: &EnvironmentId) -> PathBuf {
        self.nebula_dir
            .join("objects/environments")
            .join(format!("{}.json", safe_name(id.as_str())))
    }

    fn integration_path(&self, provider: &str) -> PathBuf {
        self.nebula_dir
            .join("objects/integrations")
            .join(format!("{}.json", safe_name(provider)))
    }

    fn secret_path(&self, id: &SecretFileRefId) -> PathBuf {
        self.nebula_dir
            .join("objects/secrets")
            .join(format!("{}.json", safe_name(id.as_str())))
    }

    fn read_json<T: for<'de> Deserialize<'de>>(&self, path: &Path) -> Result<T> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        serde_json::from_str(&content)
            .with_context(|| format!("failed to parse {}", path.display()))
    }

    fn write_json<T: Serialize>(&self, path: &Path, value: &T) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let content = serde_json::to_string_pretty(value)?;
        atomic_write(path, format!("{content}\n").as_bytes())?;
        Ok(())
    }
}

fn ensure_child_path(root: &Path, path: &Path) -> Result<()> {
    let root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    let absolute = if path.exists() {
        path.canonicalize()?
    } else {
        path.parent()
            .and_then(|parent| parent.canonicalize().ok())
            .map(|parent| parent.join(path.file_name().unwrap_or_default()))
            .unwrap_or_else(|| path.to_path_buf())
    };
    if !absolute.starts_with(&root) {
        bail!("path escapes Nebula repository root: {}", path.display());
    }
    Ok(())
}

fn atomic_write(path: impl AsRef<Path>, bytes: &[u8]) -> Result<()> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let temp_path = path.with_file_name(format!(
        ".nebula-tmp-{}-{}",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("write"),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default()
    ));
    {
        let mut file = fs::File::create(&temp_path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    fs::rename(&temp_path, path)?;
    if let Some(parent) = path.parent() {
        sync_directory(parent)?;
    }
    Ok(())
}

fn atomic_copy(source: impl AsRef<Path>, destination: impl AsRef<Path>) -> Result<()> {
    let destination = destination.as_ref();
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    let temp_path = destination.with_file_name(format!(
        ".nebula-tmp-{}-{}",
        destination
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("copy"),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default()
    ));
    fs::copy(source, &temp_path)?;
    fs::rename(&temp_path, destination)?;
    if let Some(parent) = destination.parent() {
        sync_directory(parent)?;
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<()> {
    match fs::File::open(path).and_then(|file| file.sync_all()) {
        Ok(()) => Ok(()),
        Err(error) if cfg!(not(unix)) && error.kind() == std::io::ErrorKind::PermissionDenied => {
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

fn verify_blob_bytes(blob: &ContentBlob, bytes: &[u8]) -> Result<()> {
    let actual = ContentHash::sha256(bytes);
    if actual != blob.hash || bytes.len() as u64 != blob.size_bytes {
        bail!(
            "blob checksum mismatch: expected {}:{} ({} bytes), got {}:{} ({} bytes)",
            blob.hash.algorithm,
            blob.hash.digest,
            blob.size_bytes,
            actual.algorithm,
            actual.digest,
            bytes.len()
        );
    }
    Ok(())
}

fn verify_blob_path(blob: &ContentBlob, path: &Path) -> Result<()> {
    let (actual, size_bytes) = ContentHash::sha256_reader(fs::File::open(path)?)?;
    if actual != blob.hash || size_bytes != blob.size_bytes {
        bail!(
            "blob checksum mismatch: expected {}:{} ({} bytes), got {}:{} ({} bytes)",
            blob.hash.algorithm,
            blob.hash.digest,
            blob.size_bytes,
            actual.algorithm,
            actual.digest,
            size_bytes
        );
    }
    Ok(())
}

fn content_blob_from_path(path: &Path) -> Result<ContentBlob> {
    let (hash, size_bytes) = ContentHash::sha256_reader(fs::File::open(path)?)?;
    Ok(ContentBlob {
        id: BlobId::from_hash(&hash),
        hash,
        size_bytes,
        media_type: None,
        visibility: BlobVisibility::Public,
    })
}

fn matches_tree_entry_content(
    output_path: &Path,
    blob_path: &Path,
    entry: &TreeEntry,
) -> Result<bool> {
    match entry.kind {
        TreeEntryKind::Symlink => {
            if !output_path.is_symlink() {
                return Ok(false);
            }
            let existing = fs::read_link(output_path)?.to_string_lossy().into_owned();
            let expected = fs::read_to_string(blob_path)?;
            Ok(existing == expected)
        }
        TreeEntryKind::File | TreeEntryKind::Executable => {
            if !output_path.is_file() {
                return Ok(false);
            }
            let Some(hash) = &entry.hash else {
                return Ok(false);
            };
            let (actual_hash, size_bytes) =
                ContentHash::sha256_reader(fs::File::open(output_path)?)?;
            Ok(&actual_hash == hash && Some(size_bytes) == entry.size_bytes)
        }
        TreeEntryKind::Directory => Ok(output_path.is_dir()),
    }
}

fn enforce_existing_kind(path: &Path, kind: &TreeEntryKind) -> Result<()> {
    match kind {
        TreeEntryKind::File => {
            if path.is_symlink() || !path.is_file() {
                bail!("materialized path has wrong kind: {}", path.display());
            }
        }
        TreeEntryKind::Executable => {
            if path.is_symlink() || !path.is_file() {
                bail!("materialized executable has wrong kind: {}", path.display());
            }
            make_executable(path)?;
        }
        TreeEntryKind::Symlink => {
            if !path.is_symlink() {
                bail!("materialized symlink has wrong kind: {}", path.display());
            }
        }
        TreeEntryKind::Directory => {
            if !path.is_dir() || path.is_symlink() {
                bail!("materialized directory has wrong kind: {}", path.display());
            }
        }
    }
    Ok(())
}

fn remove_atomic_write_temps(root: &Path) -> Result<()> {
    if !root.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.is_dir() {
            remove_atomic_write_temps(&path)?;
            continue;
        }
        let is_temp = path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with(".nebula-tmp-"));
        if is_temp {
            fs::remove_file(path)?;
        }
    }
    Ok(())
}

#[cfg(unix)]
fn make_executable(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_mode(permissions.mode() | 0o111);
    fs::set_permissions(path, permissions)?;
    Ok(())
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn is_executable(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;

    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn is_executable(_metadata: &fs::Metadata) -> bool {
    false
}

#[cfg(unix)]
fn create_symlink(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::os::unix::fs::symlink;

    let target = std::str::from_utf8(bytes).context("symlink target must be valid UTF-8")?;
    symlink(target, path)?;
    Ok(())
}

#[cfg(not(unix))]
fn create_symlink(path: &Path, bytes: &[u8]) -> Result<()> {
    atomic_write(path, bytes)
}

#[allow(dead_code)]
fn should_skip(relative: &Path) -> bool {
    let Some(first) = relative.components().next() else {
        return true;
    };
    let first = first.as_os_str().to_string_lossy();
    if matches!(
        first.as_ref(),
        ".nebula"
            | ".git"
            | ".agents"
            | ".cursor"
            | ".mastra"
            | "target"
            | "node_modules"
            | ".next"
            | ".turbo"
    ) {
        return true;
    }
    relative
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            name == ".DS_Store"
                || name == "tsconfig.tsbuildinfo"
                || name == "zero.db"
                || name == "zero.db-shm"
                || name == "zero.db-wal"
                || name == "zero.db-wal2"
        })
}

#[allow(dead_code)]
fn path_to_repo_string(path: &Path) -> String {
    path.components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

fn safe_name(raw: &str) -> String {
    raw.chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

fn read_json_from_path<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let content = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&content)?)
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or_default()
}

fn empty_catalog(workspace_id: WorkspaceId) -> LocalWorkspaceCatalog {
    LocalWorkspaceCatalog {
        workspace_id,
        materialized_paths: BTreeSet::new(),
        dirty_paths: BTreeSet::new(),
        indexed_paths: BTreeMap::new(),
        cached_blob_paths: BTreeSet::new(),
        last_scan_unix_ms: now_unix_ms(),
    }
}

fn remote_path(url: &str) -> Result<PathBuf> {
    if let Some(path) = url.strip_prefix("file://") {
        return Ok(PathBuf::from(path));
    }
    if url.starts_with("http://") || url.starts_with("https://") || url.starts_with("nebula://") {
        bail!(
            "experimental: network remotes are not implemented for local bundle sync; use file:// or a local bundle path"
        );
    }
    Ok(PathBuf::from(url))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_names_replace_path_hostile_chars() {
        assert_eq!(safe_name("sha256:abc/def"), "sha256_abc_def");
    }

    #[test]
    fn local_loop_can_save_propose_merge_policy_and_sync() {
        let root = unique_temp_dir("nebula-local-loop");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("app.txt"), "hello").unwrap();

        let repo = LocalRepo::init(&root).unwrap();
        repo.mark_dirty_path("app.txt".to_string()).unwrap();
        let save = repo.save(Some("initial save".to_string())).unwrap();
        assert_eq!(save.diff.entries.len(), 1);

        let proposal = repo
            .propose("main".to_string(), "Initial".to_string())
            .unwrap()
            .proposal;
        let merge = repo.merge_proposal(proposal.id.as_str()).unwrap();
        assert_eq!(merge.merged_snapshot_id, save.snapshot.id);

        let policy = repo
            .set_policy("app.txt".to_string(), PolicyDecision::Allow)
            .unwrap();
        assert_eq!(policy.rules.len(), 1);
        let evaluation = repo
            .check_policy("app.txt".to_string(), PolicyAction::ExportGit)
            .unwrap();
        assert_eq!(evaluation.decision, PolicyDecision::Allow);

        let bundle_path = root.with_extension("nebula.json");
        repo.add_remote(
            "origin".to_string(),
            bundle_path.to_string_lossy().to_string(),
        )
        .unwrap();
        repo.push(Some("origin".to_string())).unwrap();
        assert!(bundle_path.exists());

        let clone_root = unique_temp_dir("nebula-local-clone");
        let clone = LocalRepo::clone_from_bundle(&clone_root, &bundle_path).unwrap();
        assert!(!clone.list_refs().unwrap().is_empty());
    }

    #[test]
    fn open_removes_only_nebula_owned_temp_files() {
        let root = unique_temp_dir("nebula-local-recovery");
        fs::create_dir_all(&root).unwrap();
        let repo = LocalRepo::init(&root).unwrap();
        drop(repo);

        let user_temp = root.join("notes.tmp-2026");
        let nebula_temp = root.join(".nebula-tmp-config-1");
        fs::write(&user_temp, "keep me").unwrap();
        fs::write(&nebula_temp, "remove me").unwrap();

        LocalRepo::open(&root).unwrap();
        assert!(user_temp.exists());
        assert!(!nebula_temp.exists());
    }

    #[test]
    fn import_bundle_rejects_corrupt_blob_bytes() {
        let root = unique_temp_dir("nebula-local-corrupt-source");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("app.txt"), "hello").unwrap();
        let repo = LocalRepo::init(&root).unwrap();
        repo.mark_dirty_path("app.txt".to_string()).unwrap();
        repo.save(Some("save".to_string())).unwrap();

        let mut bundle = repo.export_bundle().unwrap();
        bundle.blobs[0].bytes = b"corrupt".to_vec();

        let target_root = unique_temp_dir("nebula-local-corrupt-target");
        fs::create_dir_all(&target_root).unwrap();
        let target = LocalRepo::init(&target_root).unwrap();
        assert!(target.import_bundle(&bundle).is_err());
    }

    fn unique_temp_dir(prefix: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "{}-{}",
            prefix,
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }
}
