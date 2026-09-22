mod auth;

use anyhow::{Context, Result, bail};
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
use indicatif::{ProgressBar, ProgressStyle};
use nebula_core::{
    Actor, ContentHash, Environment, EnvironmentId, EnvironmentKind, EnvironmentVariable,
    EnvironmentVariableVersion, PolicyAction, PolicyDecision, ProjectionTarget, Proposal,
    ProposalId, RefId, RefTarget, ReviewState, TreeDiffKind, TreeSnapshotId, VariableAvailability,
    VariableScope, VariableSecretStorageMode, VariableSensitivity, VariableValueKind,
    VectorIndexManifestId,
};
use nebula_local::{LocalBlobRecord, LocalRepo, LocalSyncBundle};
use nebula_sync::{RegistrySyncClient, is_registry_remote};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Parser)]
#[command(name = "neb")]
#[command(about = "Nebula vector-native source control")]
struct NebCli {
    #[arg(long, global = true)]
    json: bool,
    #[arg(long, short, global = true)]
    quiet: bool,
    #[arg(long, short, global = true)]
    verbose: bool,
    #[arg(long, global = true)]
    no_color: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, Debug)]
struct CliOutput {
    json: bool,
    quiet: bool,
    verbose: bool,
    no_color: bool,
}

#[derive(Debug, Subcommand)]
enum Command {
    Init,
    Clone {
        remote: String,
    },
    Status,
    Diff,
    Save {
        #[arg(short, long)]
        message: Option<String>,
    },
    Push {
        remote: Option<String>,
        reference: Option<String>,
    },
    Pull {
        remote: Option<String>,
        reference: Option<String>,
    },
    Remote {
        #[command(subcommand)]
        command: RemoteCommand,
    },
    Auth {
        #[command(subcommand)]
        command: AuthCommand,
    },
    Workspace {
        #[command(subcommand)]
        command: WorkspaceCommand,
    },
    Propose {
        #[arg(long)]
        target: String,
        #[arg(long)]
        title: String,
    },
    Proposal {
        #[command(subcommand)]
        command: ProposalCommand,
    },
    Ref {
        #[command(subcommand)]
        command: RefCommand,
    },
    Merge {
        proposal_id: String,
    },
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
    Secret {
        #[command(subcommand)]
        command: SecretCommand,
    },
    Vector {
        #[command(subcommand)]
        command: VectorCommand,
    },
    Git {
        #[command(subcommand)]
        command: GitCommand,
    },
    Env {
        #[command(subcommand)]
        command: EnvCommand,
    },
    Integration {
        #[command(subcommand)]
        command: IntegrationCommand,
    },
    Projection {
        #[command(subcommand)]
        command: ProjectionCommand,
    },
    Ops {
        #[arg(long)]
        report_file: Option<std::path::PathBuf>,
        #[arg(long)]
        report_webhook: Option<String>,
        #[command(subcommand)]
        command: OpsCommand,
    },
    Galaxy {
        #[command(subcommand)]
        command: GalaxyCommand,
    },
    Completions {
        shell: Shell,
    },
    Man,
}

#[derive(Debug, Subcommand)]
enum GalaxyCommand {
    Create {
        name: String,
        #[arg(long)]
        registry_url: Option<String>,
        #[arg(long, default_value = "origin")]
        remote: String,
        #[arg(long)]
        org: Option<String>,
    },
    DeployConfig {
        #[command(subcommand)]
        command: DeployConfigCommand,
    },
    Policy {
        #[command(subcommand)]
        command: GalaxyPolicyCommand,
    },
    /// Lists galaxies you're authorized to see.
    List {
        #[arg(long)]
        org: Option<String>,
        #[arg(long)]
        registry_url: Option<String>,
        #[arg(long, default_value = "origin")]
        remote: String,
    },
    /// Shows a single galaxy's details.
    Get {
        /// Galaxy id (repo_...) or owner/name.
        galaxy: String,
        #[arg(long)]
        registry_url: Option<String>,
        #[arg(long, default_value = "origin")]
        remote: String,
    },
}

/// Manages a galaxy's actor-authorization policies. The registry's
/// authorization engine fails closed by default: even a token whose scope
/// includes an action (e.g. `manage_deploy_config`) is denied until an
/// explicit allow rule also exists for that actor. Requires a token with
/// `nebula.repository:manage_auth` — granting access to other actors is an
/// admin operation, not a self-service one.
#[derive(Debug, Subcommand)]
enum GalaxyPolicyCommand {
    Grant {
        /// Galaxy id (repo_...) or owner/name.
        galaxy: String,
        /// "public", or "<kind>:<id>" where kind is user, team, agent, or
        /// integration (e.g. "integration:ci-deploy-config").
        actor: String,
        /// Action to allow, e.g. "manage_deploy_config" or "sync_objects".
        /// Repeat for multiple actions.
        #[arg(long = "action", required = true)]
        actions: Vec<String>,
        #[arg(long, default_value_t = 0)]
        priority: i32,
        #[arg(long)]
        reason: Option<String>,
        /// Scope this grant to one specific auth token (tok_...), so other
        /// tokens/sessions belonging to the same actor are not covered by
        /// it. Useful because Better Auth API keys all resolve to the same
        /// `user:<id>` actor — this is the only way to grant policy to one
        /// CI token distinctly from the account's other credentials. Find a
        /// token's id with `neb auth token list`. Omit for an account-wide
        /// grant (the default, backward-compatible behavior).
        #[arg(long = "token")]
        token_id: Option<String>,
        #[arg(long)]
        registry_url: Option<String>,
        #[arg(long, default_value = "origin")]
        remote: String,
    },
    /// Lists the actor-authorization policies granted on a galaxy.
    List {
        galaxy: String,
        #[arg(long)]
        registry_url: Option<String>,
        #[arg(long, default_value = "origin")]
        remote: String,
    },
    /// Removes a previously granted policy (see `neb galaxy policy list` for
    /// ids).
    Revoke {
        galaxy: String,
        /// The policy id printed by `neb galaxy policy grant`/`list` (pol_...).
        policy_id: String,
        #[arg(long)]
        registry_url: Option<String>,
        #[arg(long, default_value = "origin")]
        remote: String,
    },
}

/// Registers or inspects a galaxy's deploy config, which tells the registry
/// where to send deploy-intent webhooks for a given service (e.g. a Horizon
/// deployment target). Requires a token with the
/// `nebula.repository:manage_deploy_config` scope — mint one with `neb auth
/// token create ci --scope nebula.repository:manage_deploy_config`.
#[derive(Debug, Subcommand)]
enum DeployConfigCommand {
    Set {
        /// Galaxy id (repo_...) or owner/name.
        galaxy: String,
        /// Identifier for the deploy target within this galaxy (e.g. a
        /// Horizon service ID). A galaxy can have multiple deploy configs,
        /// one per service.
        service_id: String,
        /// Webhook URL the registry POSTs the deploy intent to.
        #[arg(long)]
        deploy_url: String,
        /// Shared secret used to sign the webhook payload; must be at least
        /// 16 characters.
        #[arg(long)]
        signing_secret: String,
        #[arg(long, default_value = "horizon")]
        provider_key: String,
        #[arg(long)]
        environment_id: Option<String>,
        #[arg(long)]
        environment_name: Option<String>,
        #[arg(long)]
        context_path: Option<String>,
        /// Create a deploy intent when the galaxy default ref is updated (default: true).
        #[arg(long = "auto-deploy", default_value_t = true)]
        #[arg(long = "no-auto-deploy", action = clap::ArgAction::SetFalse)]
        auto_deploy: bool,
        #[arg(long)]
        registry_url: Option<String>,
        #[arg(long, default_value = "origin")]
        remote: String,
    },
    Get {
        galaxy: String,
        service_id: String,
        #[arg(long)]
        registry_url: Option<String>,
        #[arg(long, default_value = "origin")]
        remote: String,
    },
    Delete {
        galaxy: String,
        service_id: String,
        #[arg(long)]
        registry_url: Option<String>,
        #[arg(long, default_value = "origin")]
        remote: String,
    },
}

#[derive(Debug, Subcommand)]
enum WorkspaceCommand {
    Create {
        name: String,
        #[arg(long)]
        from: String,
    },
    List,
    Switch {
        name: String,
    },
    Dirty {
        path: String,
    },
}

#[derive(Debug, Subcommand)]
enum RemoteCommand {
    Add { name: String, url: String },
    List,
    Remove { name: String },
}

#[derive(Debug, Subcommand)]
enum AuthCommand {
    Register {
        #[arg(long)]
        registry_url: Option<String>,
        #[arg(long, default_value = "origin")]
        remote: String,
        #[arg(long)]
        email: Option<String>,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        password: Option<String>,
    },
    Login {
        #[arg(long)]
        registry_url: Option<String>,
        #[arg(long, default_value = "origin")]
        remote: String,
        #[arg(long)]
        token: Option<String>,
        #[arg(long)]
        email: Option<String>,
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        org: Option<String>,
        #[arg(long)]
        repository: Option<String>,
        #[arg(long = "scope")]
        scopes: Vec<String>,
    },
    Status {
        #[arg(long)]
        registry_url: Option<String>,
        #[arg(long)]
        remote: Option<String>,
    },
    Logout {
        #[arg(long)]
        registry_url: Option<String>,
        #[arg(long, default_value = "origin")]
        remote: String,
    },
    Token {
        #[command(subcommand)]
        command: AuthTokenCommand,
    },
    /// Shows the actor identity, scopes, and repository binding your current
    /// credential resolves to. Use the printed `actor` value directly with
    /// `neb galaxy policy grant` — it's usually `user:<id>`, not the token's
    /// display name.
    Whoami {
        #[arg(long)]
        registry_url: Option<String>,
        #[arg(long, default_value = "origin")]
        remote: String,
    },
}

#[derive(Debug, Subcommand)]
enum AuthTokenCommand {
    Create {
        name: String,
        #[arg(long)]
        registry_url: Option<String>,
        #[arg(long, default_value = "origin")]
        remote: String,
        #[arg(long)]
        org: Option<String>,
        #[arg(long)]
        repository: Option<String>,
        #[arg(long = "scope")]
        scopes: Vec<String>,
        #[arg(long)]
        expires_in_days: Option<i64>,
    },
    List {
        #[arg(long)]
        registry_url: Option<String>,
        #[arg(long, default_value = "origin")]
        remote: String,
    },
    Revoke {
        id: String,
        #[arg(long)]
        registry_url: Option<String>,
        #[arg(long, default_value = "origin")]
        remote: String,
    },
}

#[derive(Debug, Subcommand)]
enum ProposalCommand {
    Status { proposal_id: Option<String> },
    List,
    Close { proposal_id: String },
}

#[derive(Debug, Subcommand)]
enum RefCommand {
    List,
    Show { name: String },
}

#[derive(Debug, Subcommand)]
enum PolicyCommand {
    Set { path: String, decision: String },
    List,
    Check { path: String, action: String },
}

#[derive(Debug, Subcommand)]
enum SecretCommand {
    Add { name: String },
    Inject { name: String, environment: String },
}

#[derive(Debug, Subcommand)]
enum VectorCommand {
    Index {
        snapshot_id: Option<String>,
        #[arg(long, default_value = "origin")]
        remote: String,
    },
    Search {
        query: String,
        #[arg(long)]
        manifest_id: Option<String>,
        #[arg(long, default_value = "origin")]
        remote: String,
    },
    Explain {
        path: String,
        #[arg(long)]
        manifest_id: String,
        #[arg(long, default_value = "origin")]
        remote: String,
    },
}

#[derive(Debug, Subcommand)]
enum GitCommand {
    Mirror {
        remote: String,
        #[arg(long)]
        mirror_path: String,
    },
    Migrate {
        repo: String,
        #[arg(long, default_value = "refs/git-migration")]
        namespace: String,
        #[arg(long, default_value = "pointers")]
        lfs: String,
        #[arg(long)]
        mirror_path: Option<String>,
        #[arg(long)]
        verify: bool,
    },
    Import {
        remote: String,
        #[arg(long)]
        execute: bool,
        #[arg(long)]
        mirror_path: Option<String>,
    },
    Export {
        target: String,
        #[arg(long)]
        execute: bool,
        #[arg(long)]
        worktree: Option<String>,
    },
    Pr {
        proposal_id: String,
    },
}

#[derive(Debug, Subcommand)]
enum OpsCommand {
    Migration,
    Consistency {
        #[command(subcommand)]
        command: OpsConsistencyCommand,
    },
    Retention {
        #[command(subcommand)]
        command: OpsRetentionCommand,
    },
    Backup {
        #[command(subcommand)]
        command: OpsBackupCommand,
    },
    Restore {
        #[command(subcommand)]
        command: OpsRestoreCommand,
    },
    Registry {
        #[command(subcommand)]
        command: OpsRegistryCommand,
    },
}

#[derive(Debug, Subcommand)]
enum OpsRegistryCommand {
    /// Import a file-backed registry.json into Postgres + object store.
    ImportFile {
        /// Path to registry.json
        #[arg(long)]
        source: PathBuf,
        /// Optional on-disk blob-store directory to copy (e.g. /data/blob-store)
        #[arg(long)]
        source_blob_store: Option<PathBuf>,
        /// Dry-run: parse and count without writing
        #[arg(long)]
        dry_run: bool,
        /// Run SQL migrations before import
        #[arg(long, default_value_t = true)]
        run_migrations: bool,
    },
}

#[derive(Debug, Subcommand)]
enum OpsConsistencyCommand {
    Check,
    Repair {
        #[arg(long)]
        execute: bool,
    },
}

#[derive(Debug, Subcommand)]
enum OpsRetentionCommand {
    Cleanup {
        #[arg(long)]
        execute: bool,
    },
    Plan,
}

#[derive(Debug, Subcommand)]
enum OpsBackupCommand {
    Plan {
        metadata_uri: String,
        blob_uri: String,
        #[arg(long)]
        vector_uri: Option<String>,
    },
    Drill {
        #[arg(long, default_value = "managed")]
        tool: String,
        #[arg(long)]
        execute: bool,
        #[arg(long)]
        operator: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum OpsRestoreCommand {
    Plan {
        metadata_uri: String,
        blob_uri: String,
        #[arg(long)]
        vector_uri: Option<String>,
    },
    Drill {
        #[arg(long)]
        target: String,
        #[arg(long)]
        backup_id: Option<String>,
        #[arg(long, default_value = "managed")]
        tool: String,
        #[arg(long)]
        execute: bool,
        #[arg(long)]
        operator: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum EnvCommand {
    List {
        #[arg(long)]
        environment: Option<String>,
    },
    Create {
        name: String,
    },
    Configure {
        name: String,
    },
    Set {
        key: String,
        #[arg(long)]
        value: Option<String>,
        #[arg(long, default_value = "development")]
        environment: String,
        #[arg(long)]
        service: Option<String>,
        #[arg(long = "scope")]
        availability: Vec<String>,
        #[arg(long)]
        sensitive: bool,
        #[arg(long)]
        sealed: bool,
        #[arg(long)]
        save: bool,
    },
    Seal {
        key: String,
        #[arg(long, default_value = "production")]
        environment: String,
        #[arg(long)]
        service: Option<String>,
    },
    Export {
        #[arg(long, default_value = "development")]
        environment: String,
    },
    Diff,
}

#[derive(Debug, Subcommand)]
enum IntegrationCommand {
    Add { provider: String },
    Configure { provider: String },
    Test { provider: String },
}

#[derive(Debug, Subcommand)]
enum ProjectionCommand {
    Preview {
        #[arg(long)]
        environment: String,
        #[arg(long)]
        target: String,
    },
    Export {
        #[arg(long)]
        environment: String,
        #[arg(long)]
        target: String,
    },
}

fn main() -> Result<()> {
    let cli = NebCli::parse();
    let output = CliOutput {
        json: cli.json,
        quiet: cli.quiet,
        verbose: cli.verbose,
        no_color: cli.no_color,
    };
    run_command(cli.command, output)
}

fn run_command(command: Command, output: CliOutput) -> Result<()> {
    let _ = (output.verbose, output.no_color);
    match command {
        Command::Init => {
            let repo = LocalRepo::init(std::env::current_dir()?)?;
            println!("Initialized Nebula repository at {}", repo_path_hint(&repo));
        }
        Command::Clone { remote } => {
            let repo = if let Some(remote) = parse_registry_clone_remote(&remote) {
                let bundle = block_on_sync(
                    sync_client(remote.registry_url)?.get_bundle(&remote.repository_id),
                )?;
                LocalRepo::clone_from_bundle_data(
                    std::env::current_dir()?,
                    remote.remote_url,
                    &bundle,
                )?
            } else {
                LocalRepo::clone_from_bundle(std::env::current_dir()?, remote)?
            };
            if output.json {
                print_json(json!({
                    "ok": true,
                    "command": "clone",
                    "path": repo_path_hint(&repo),
                }))?;
            } else if !output.quiet {
                println!("Cloned Nebula repository into {}", repo_path_hint(&repo));
            }
        }
        Command::Status => {
            let repo = open_repo()?;
            let status = repo.status()?;
            if output.json {
                print_json(json!({
                    "workspace": status.workspace.name,
                    "changed": status.diff.entries.len(),
                    "entries": status.diff.entries.iter().map(|entry| {
                        json!({
                            "path": entry.path,
                            "kind": format!("{:?}", entry.kind),
                        })
                    }).collect::<Vec<_>>(),
                }))?;
            } else if !output.quiet {
                print_repo_header(&output, &repo, status.diff.entries.len());
                println!("Workspace: {}", status.workspace.name);
                print_diff_summary(&status.diff);
            }
        }
        Command::Diff => {
            let repo = open_repo()?;
            let diff = repo.diff()?;
            if !output.json && !output.quiet {
                print_repo_header(&output, &repo, diff.entries.len());
            }
            print_diff_entries(&diff.entries);
            println!(
                "Compared {} tree node(s), skipped {} unchanged subtree(s).",
                diff.compared_tree_nodes, diff.skipped_equal_tree_nodes
            );
        }
        Command::Save { message } => {
            let repo = open_repo()?;
            let result = repo.save(message)?;
            if !output.json && !output.quiet {
                print_repo_header(&output, &repo, result.diff.entries.len());
            }
            println!("Saved snapshot {}", result.snapshot.id);
            println!("Created changeset {}", result.changeset.id);
            print_diff_summary(&result.diff);
        }
        Command::Push { remote, reference } => {
            if let Some(reference) = reference {
                println!(
                    "experimental: reference-scoped push is not implemented yet; pushing the full bundle for {reference}."
                );
            }
            let repo = open_repo()?;
            if let Some(url) = remote_registry_url(&repo, remote.clone())? {
                let progress = progress_spinner(output, "Pushing Nebula objects to registry");
                let remote_repo_id = remote_full_url(&repo, remote)
                    .and_then(|u| parse_neb_remote_url(&u))
                    .map(|parsed| parsed.repository_id);
                let bundle = block_on_sync(sync_client(url)?.push_repo(&repo, remote_repo_id))?;
                finish_progress(progress, "Push complete");
                if output.json {
                    print_json(json!({
                        "ok": true,
                        "command": "push",
                        "snapshots": bundle.snapshots.len(),
                        "changesets": bundle.changesets.len(),
                        "proposals": bundle.proposals.len(),
                        "blobs": bundle.blobs.len(),
                    }))?;
                } else if !output.quiet {
                    println!(
                        "Pushed {} snapshot(s), {} changeset(s), {} proposal(s), {} blob(s) to registry.",
                        bundle.snapshots.len(),
                        bundle.changesets.len(),
                        bundle.proposals.len(),
                        bundle.blobs.len()
                    );
                }
            } else {
                let path = repo.push(remote)?;
                if output.json {
                    print_json(json!({
                        "ok": true,
                        "command": "push",
                        "path": path,
                    }))?;
                } else if !output.quiet {
                    println!("Pushed Nebula bundle to {}", path.display());
                }
            }
        }
        Command::Pull { remote, reference } => {
            if let Some(reference) = reference {
                println!(
                    "experimental: reference-scoped pull is not implemented yet; pulling the full bundle for {reference}."
                );
            }
            let repo = open_repo()?;
            let bundle = if let Some(url) = remote_registry_url(&repo, remote.clone())? {
                let progress = progress_spinner(output, "Pulling Nebula objects from registry");
                let bundle = block_on_sync(sync_client(url)?.pull_repo(&repo))?;
                finish_progress(progress, "Pull complete");
                bundle
            } else {
                repo.pull(remote)?
            };
            if output.json {
                print_json(json!({
                    "ok": true,
                    "command": "pull",
                    "snapshots": bundle.snapshots.len(),
                    "changesets": bundle.changesets.len(),
                    "proposals": bundle.proposals.len(),
                    "blobs": bundle.blobs.len(),
                }))?;
            } else if !output.quiet {
                println!(
                    "Pulled {} snapshot(s), {} changeset(s), {} proposal(s), {} blob(s).",
                    bundle.snapshots.len(),
                    bundle.changesets.len(),
                    bundle.proposals.len(),
                    bundle.blobs.len()
                );
            }
        }
        Command::Remote { command } => {
            let repo = open_repo()?;
            match command {
                RemoteCommand::Add { name, url } => {
                    let remote = repo.add_remote(name, url)?;
                    println!("Added remote {} -> {}", remote.name, remote.url);
                }
                RemoteCommand::List => {
                    for remote in repo.list_remotes()? {
                        println!("{}\t{}", remote.name, remote.url);
                    }
                }
                RemoteCommand::Remove { name } => {
                    let remote = repo.remove_remote(&name)?;
                    println!("Removed remote {} -> {}", remote.name, remote.url);
                }
            }
        }
        Command::Auth { command } => handle_auth_command(command, output)?,
        Command::Workspace { command } => {
            let repo = open_repo()?;
            match command {
                WorkspaceCommand::Create { name, from } => {
                    let workspace = repo.create_workspace(name, from)?;
                    println!(
                        "Created workspace {} from snapshot {}",
                        workspace.name, workspace.base_snapshot_id
                    );
                }
                WorkspaceCommand::List => {
                    for workspace in repo.list_workspaces()? {
                        println!(
                            "{}\tbase={}\tlast={}",
                            workspace.name,
                            workspace.base_snapshot_id,
                            workspace
                                .last_snapshot_id
                                .as_ref()
                                .map(|id| id.as_str())
                                .unwrap_or("-")
                        );
                    }
                }
                WorkspaceCommand::Switch { name } => {
                    let workspace = repo.switch_workspace(&name)?;
                    println!("Switched to workspace {}", workspace.name);
                }
                WorkspaceCommand::Dirty { path } => {
                    let catalog = repo.mark_dirty_path(path)?;
                    println!(
                        "Tracked {} dirty path(s) for workspace {}",
                        catalog.dirty_paths.len(),
                        catalog.workspace_id
                    );
                }
            }
        }
        Command::Propose { target, title } => {
            let repo = open_repo()?;
            let result = repo.propose(target, title)?;
            println!("Created proposal {}", result.proposal.id);
        }
        Command::Proposal { command } => {
            let repo = open_repo()?;
            match command {
                ProposalCommand::List => {
                    for proposal in repo.list_proposals()? {
                        println!("{}\t{:?}\t{}", proposal.id, proposal.state, proposal.title);
                    }
                }
                ProposalCommand::Status { proposal_id } => {
                    if let Some(id) = proposal_id {
                        let proposal = repo.proposal_by_string(&id)?;
                        println!("{}\t{:?}\t{}", proposal.id, proposal.state, proposal.title);
                        println!("Target ref: {}", proposal.target_ref_id);
                        if proposal.changeset_ids.is_empty() {
                            println!("Changesets: -");
                        } else {
                            println!(
                                "Changesets: {}",
                                proposal
                                    .changeset_ids
                                    .iter()
                                    .map(|id| id.as_str())
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            );
                        }
                    } else {
                        for proposal in repo.list_proposals()? {
                            println!("{}\t{:?}\t{}", proposal.id, proposal.state, proposal.title);
                        }
                    }
                }
                ProposalCommand::Close { proposal_id } => {
                    let proposal = repo.close_proposal(&proposal_id)?;
                    println!("Closed proposal {}", proposal.id);
                }
            }
        }
        Command::Ref { command } => {
            let repo = open_repo()?;
            match command {
                RefCommand::List => {
                    for reference in repo.list_refs()? {
                        print_ref(&reference);
                    }
                }
                RefCommand::Show { name } => {
                    let reference = repo.ref_by_name(&name)?;
                    print_ref(&reference);
                }
            }
        }
        Command::Merge { proposal_id } => {
            let repo = open_repo()?;
            let result = repo.merge_proposal(&proposal_id)?;
            println!(
                "Merged proposal {} into {} at {}",
                result.proposal.id, result.target_ref.name, result.merged_snapshot_id
            );
        }
        Command::Policy { command } => {
            let repo = open_repo()?;
            match command {
                PolicyCommand::Set { path, decision } => {
                    let policy = repo.set_policy(path, parse_policy_decision(&decision)?)?;
                    println!("Created policy {}\t{}", policy.id, policy.name);
                }
                PolicyCommand::List => {
                    for policy in repo.list_policies()? {
                        println!(
                            "{}\tpriority={}\t{}",
                            policy.id, policy.priority, policy.name
                        );
                    }
                }
                PolicyCommand::Check { path, action } => {
                    let evaluation = repo.check_policy(path, parse_policy_action(&action)?)?;
                    println!("{:?}\t{}", evaluation.decision, evaluation.reason);
                    for audit in evaluation.audit {
                        println!(
                            "matched {}\tpriority={}\t{:?}\t{}",
                            audit.policy_id, audit.priority, audit.decision, audit.reason
                        );
                    }
                }
            }
        }
        Command::Secret { command } => {
            let repo = open_repo()?;
            match command {
                SecretCommand::Add { name } => {
                    let secret = repo.add_secret(name)?;
                    println!("Added secret ref {}\t{}", secret.id, secret.name);
                }
                SecretCommand::Inject { name, environment } => {
                    println!(
                        "Secret `{name}` is configured for injection planning in `{environment}`. Actual provider injection is handled by deployment grants."
                    );
                }
            }
        }
        Command::Vector { command } => {
            let repo = open_repo()?;
            let snapshot = repo.active_snapshot()?;
            match command {
                VectorCommand::Index {
                    snapshot_id,
                    remote,
                } => {
                    let remote = registry_remote_url(&repo, &remote)?;
                    let requested_snapshot = snapshot_id
                        .map(TreeSnapshotId::new)
                        .unwrap_or_else(|| snapshot.id.clone());
                    let response = block_on_sync(sync_client(remote)?.create_vector_index(
                        &snapshot.repository_id,
                        &nebula_sync::VectorIndexRequest {
                            snapshot_id: Some(requested_snapshot),
                            projection_id: None,
                            actor: Actor::Public,
                        },
                    ))?;
                    println!(
                        "experimental: vector indexing currently records path/content-hash metadata, not production semantic embeddings."
                    );
                    println!(
                        "Vector index ready manifest={}\tsnapshot={}\tchunks={}",
                        response.manifest.id,
                        response.manifest.snapshot_id,
                        response.manifest.chunk_count
                    );
                }
                VectorCommand::Search {
                    query,
                    manifest_id,
                    remote,
                } => {
                    let remote = registry_remote_url(&repo, &remote)?;
                    let response = block_on_sync(sync_client(remote)?.search_vector_index(
                        &snapshot.repository_id,
                        &nebula_sync::VectorSearchRequest {
                            manifest_id: manifest_id.map(VectorIndexManifestId::new),
                            snapshot_id: Some(snapshot.id.clone()),
                            query,
                            top_k: Some(10),
                        },
                    ))?;
                    println!("manifest={}", response.manifest_id);
                    println!(
                        "experimental: search results come from the registry path/hash index until a semantic vector backend is configured."
                    );
                    for hit in response.hits {
                        println!("{}\t{}\t{}", hit.score, hit.path, hit.snippet);
                    }
                }
                VectorCommand::Explain {
                    path,
                    manifest_id,
                    remote,
                } => {
                    let remote = registry_remote_url(&repo, &remote)?;
                    let response = block_on_sync(sync_client(remote)?.explain_vector_chunk(
                        &snapshot.repository_id,
                        &nebula_sync::VectorExplainRequest {
                            manifest_id: VectorIndexManifestId::new(manifest_id),
                            path,
                        },
                    ))?;
                    if let Some(chunk) = response.chunk {
                        println!(
                            "path={}\tmanifest={}\thash={}:{}",
                            response.path,
                            response.manifest_id,
                            chunk.content_hash.algorithm,
                            chunk.content_hash.digest
                        );
                    } else {
                        println!(
                            "path={}\tmanifest={}\tmissing=true",
                            response.path, response.manifest_id
                        );
                    }
                }
            }
        }
        Command::Git { command } => {
            let repo = open_repo()?;
            match command {
                GitCommand::Mirror {
                    remote,
                    mirror_path,
                } => {
                    let result = nebula_git::execute_git_import(remote.clone(), &mirror_path)?;
                    if output.json {
                        print_json(json!({
                            "ok": true,
                            "command": "git mirror",
                            "remote": remote,
                            "mirror_path": mirror_path,
                            "refs": result.refs.len(),
                            "tags": result.tags.len(),
                            "note": "mirror cache only; run git migrate to convert into Nebula snapshots",
                        }))?;
                    } else if !output.quiet {
                        println!("Mirrored Git repository for inspection/cache only.");
                        println!("remote={remote}");
                        println!("mirror_path={}", result.mirror_path.display());
                        println!("refs={}", result.refs.len());
                        println!("tags={}", result.tags.len());
                        println!(
                            "Run `neb git migrate {}` to convert Git history into Nebula.",
                            result.mirror_path.display()
                        );
                    }
                }
                GitCommand::Migrate {
                    repo: git_repo,
                    namespace,
                    lfs,
                    mirror_path,
                    verify,
                } => {
                    let source = git_migration_source(&git_repo, mirror_path.as_deref())?;
                    let config = repo.config()?;
                    let migration = nebula_git::migrate_git_repository(
                        &source,
                        nebula_git::GitMigrationOptions {
                            repository_id: config.repository_id.clone(),
                            ref_namespace: namespace.clone(),
                            lfs_strategy: parse_lfs_strategy(&lfs)?,
                        },
                    )?;
                    let verification = nebula_git::verify_git_migration(&migration);
                    if verify && !verification.valid {
                        bail!(
                            "Git migration verification failed: {}",
                            verification.errors.join("; ")
                        );
                    }
                    let bundle = migration_bundle(config.default_ref, migration.clone());
                    repo.import_bundle(&bundle)?;
                    if output.json {
                        print_json(json!({
                            "ok": verification.valid,
                            "command": "git migrate",
                            "source": source,
                            "namespace": namespace,
                            "snapshots": migration.snapshots.len(),
                            "refs": migration.refs.len(),
                            "blobs": migration.blobs.len(),
                            "warnings": verification.warnings,
                            "errors": verification.errors,
                        }))?;
                    } else if !output.quiet {
                        println!("Migrated Git history into Nebula-native snapshots.");
                        println!("source={}", source.display());
                        println!("namespace={namespace}");
                        println!("snapshots={}", migration.snapshots.len());
                        println!("refs={}", migration.refs.len());
                        println!("blobs={}", migration.blobs.len());
                        for warning in verification.warnings {
                            println!("warning: {warning}");
                        }
                    }
                }
                GitCommand::Import {
                    remote,
                    execute,
                    mirror_path,
                } => {
                    let plan = nebula_git::plan_git_import(remote.clone());
                    println!("Git mirror inspection plan for {}", plan.remote);
                    println!("refs={}", plan.imported_refs.join(", "));
                    println!("preserves_history={}", plan.preserves_history);
                    println!("lfs_compatible={}", plan.supports_lfs);
                    println!(
                        "experimental: `neb git import` is mirror-only and deprecated; use `neb git mirror` or `neb git migrate`."
                    );
                    if execute {
                        let mirror_path = mirror_path.ok_or_else(|| {
                            anyhow::anyhow!("--mirror-path is required with --execute")
                        })?;
                        let result = nebula_git::execute_git_import(remote, mirror_path)?;
                        println!("mirrored_refs={}", result.refs.len());
                        println!("mirrored_tags={}", result.tags.len());
                    }
                }
                GitCommand::Export {
                    target,
                    execute,
                    worktree,
                } => {
                    let snapshot = repo.active_snapshot()?;
                    let decisions = projection_decisions(&repo, &snapshot)?;
                    let environment = cli_environment(&snapshot, "production");
                    let proposal = Proposal {
                        id: ProposalId::generated(),
                        repository_id: snapshot.repository_id.clone(),
                        title: "local git export".to_string(),
                        target_ref_id: RefId::generated(),
                        changeset_ids: Vec::new(),
                        state: ReviewState::Open,
                        policy_checks: Vec::new(),
                    };
                    let projection = nebula_git::plan_git_projection(
                        &snapshot,
                        &proposal,
                        nebula_git::GitProjectionRequest {
                            actor: Actor::Public,
                            environment,
                            target: ProjectionTarget::GitRemote(target.clone()),
                            path_decisions: decisions,
                        },
                    )?;
                    let plan = nebula_git::plan_git_export(
                        &snapshot,
                        &projection.manifest,
                        target,
                        "nebula-export",
                    );
                    println!("Git export plan branch={}", plan.branch);
                    println!("snapshot={}", plan.snapshot_id);
                    println!("included={}", plan.included_paths.len());
                    println!("omitted={}", plan.omitted_paths.len());
                    println!("lfs_compatible={}", plan.lfs_compatible);
                    if execute {
                        let worktree = worktree.ok_or_else(|| {
                            anyhow::anyhow!("--worktree is required with --execute")
                        })?;
                        let blob_bytes = repo.blob_bytes_for_snapshot(&snapshot)?;
                        let materialized = nebula_git::materialize_projection(
                            &projection,
                            &snapshot,
                            &blob_bytes,
                            &worktree,
                        )?;
                        let result = nebula_git::execute_git_export_plan(&plan, worktree)?;
                        println!("materialized_paths={}", materialized.written_paths.len());
                        println!("executed_git_commands={}", result.commands.len());
                    }
                }
                GitCommand::Pr { proposal_id } => {
                    let proposal = repo.proposal_by_string(&proposal_id)?;
                    let plan = nebula_git::plan_github_pr(
                        &proposal,
                        format!("nebula/{}", proposal.id.as_str()),
                    );
                    println!("GitHub PR plan for proposal {}", plan.proposal_id);
                    println!("branch={}", plan.branch);
                    println!("title={}", plan.title);
                    println!("{}", plan.body);
                }
            }
        }
        Command::Env { command } => {
            let repo = open_repo()?;
            match command {
                EnvCommand::List { environment } => {
                    if let Some(environment_name) = environment {
                        let environment = ensure_local_environment(&repo, &environment_name)?;
                        let versions = repo.list_environment_variable_versions()?;
                        for variable in repo
                            .list_environment_variables()?
                            .into_iter()
                            .filter(|variable| variable.environment_id == environment.id)
                        {
                            let version = variable
                                .current_version_id
                                .as_ref()
                                .and_then(|id| versions.iter().find(|version| &version.id == id));
                            let masked = version
                                .and_then(|version| version.fingerprint.as_deref())
                                .map(|fingerprint| {
                                    masked_fingerprint(&variable.sensitivity, fingerprint)
                                })
                                .unwrap_or_else(|| "[unset]".to_string());
                            println!(
                                "{}\t{}\t{:?}\t{:?}\t{}",
                                variable.key,
                                variable.scope.stable_key(),
                                variable.availability,
                                variable.sensitivity,
                                masked
                            );
                        }
                    } else {
                        for environment in repo.list_environments()? {
                            println!(
                                "{}\t{}\t{:?}",
                                environment.id, environment.name, environment.kind
                            );
                        }
                    }
                }
                EnvCommand::Create { name } => {
                    let environment = repo.create_environment(name)?;
                    println!(
                        "Created environment {}\t{}",
                        environment.id, environment.name
                    );
                }
                EnvCommand::Configure { name } => {
                    let environment = repo.create_environment(name)?;
                    println!(
                        "Configured environment {}\t{}",
                        environment.id, environment.name
                    );
                }
                EnvCommand::Set {
                    key,
                    value,
                    environment,
                    service,
                    availability,
                    sensitive,
                    sealed,
                    save,
                } => {
                    let environment = ensure_local_environment(&repo, &environment)?;
                    let value = match value {
                        Some(value) => value,
                        None => rpassword::prompt_password(format!("{key}: "))?,
                    };
                    let sensitivity = if sealed {
                        VariableSensitivity::Sealed
                    } else if sensitive || save || likely_secret_key(&key) {
                        VariableSensitivity::Sensitive
                    } else {
                        VariableSensitivity::Encrypted
                    };
                    let scope = service
                        .map(|service_id| VariableScope::Service { service_id })
                        .unwrap_or(VariableScope::Shared);
                    let availability = parse_variable_availability(availability)?;
                    let variable_id = EnvironmentVariable::stable_id(
                        &environment.repository_id,
                        &environment.id,
                        &scope,
                        &key,
                    );
                    let now = now_unix_ms();
                    let version = EnvironmentVariableVersion {
                        id: nebula_core::EnvironmentVariableVersionId::generated(),
                        repository_id: environment.repository_id.clone(),
                        variable_id: variable_id.clone(),
                        key: key.clone(),
                        sensitivity: sensitivity.clone(),
                        value_kind: if sensitivity.is_write_only() {
                            VariableValueKind::Secret
                        } else {
                            VariableValueKind::Literal
                        },
                        storage_mode: if save {
                            VariableSecretStorageMode::BlobBackedEncrypted
                        } else if sensitivity.is_write_only() {
                            VariableSecretStorageMode::MetadataOnly
                        } else {
                            VariableSecretStorageMode::RegistryEncrypted
                        },
                        plaintext_value: (!sensitivity.is_write_only()).then_some(value.clone()),
                        ciphertext: None,
                        content_hash: None,
                        encryption_key_id: None,
                        wrapped_data_key: None,
                        nonce: None,
                        fingerprint: Some(local_fingerprint(&key, &value)),
                        value_digest: Some(ContentHash::sha256(value.as_bytes()).digest),
                        redaction_tokens: Vec::new(),
                        created_by: Some(Actor::Public),
                        created_at_unix_ms: now,
                        last_injected_at_unix_ms: None,
                        last_used_by_deploy_id: None,
                    };
                    let variable = EnvironmentVariable {
                        id: variable_id,
                        repository_id: environment.repository_id,
                        workspace_id: None,
                        environment_id: environment.id,
                        scope,
                        key: key.clone(),
                        value_kind: version.value_kind.clone(),
                        availability,
                        sensitivity: sensitivity.clone(),
                        storage_mode: version.storage_mode.clone(),
                        current_version_id: Some(version.id.clone()),
                        reference: None,
                        created_by: Some(Actor::Public),
                        updated_by: Some(Actor::Public),
                        created_at_unix_ms: now,
                        updated_at_unix_ms: now,
                    };
                    repo.write_environment_variable_version(&version)?;
                    repo.write_environment_variable(&variable)?;
                    println!(
                        "Set {}\t{:?}\t{}",
                        key,
                        sensitivity,
                        masked_fingerprint(
                            &sensitivity,
                            version.fingerprint.as_deref().unwrap_or("")
                        )
                    );
                }
                EnvCommand::Seal {
                    key,
                    environment,
                    service,
                } => {
                    let environment = ensure_local_environment(&repo, &environment)?;
                    let scope = service
                        .map(|service_id| VariableScope::Service { service_id })
                        .unwrap_or(VariableScope::Shared);
                    let variable_id = EnvironmentVariable::stable_id(
                        &environment.repository_id,
                        &environment.id,
                        &scope,
                        &key,
                    );
                    let variables = repo.list_environment_variables()?;
                    let Some(mut variable) = variables
                        .into_iter()
                        .find(|variable| variable.id == variable_id)
                    else {
                        bail!("environment variable `{key}` is not configured");
                    };
                    variable.sensitivity = VariableSensitivity::Sealed;
                    variable.updated_at_unix_ms = now_unix_ms();
                    repo.write_environment_variable(&variable)?;
                    println!("Sealed {key}; sealed values cannot be unsealed or exported.");
                }
                EnvCommand::Export { environment } => {
                    let environment = ensure_local_environment(&repo, &environment)?;
                    let versions = repo.list_environment_variable_versions()?;
                    for variable in repo
                        .list_environment_variables()?
                        .into_iter()
                        .filter(|variable| variable.environment_id == environment.id)
                    {
                        if variable.sensitivity.is_write_only() {
                            println!(
                                "# {} is {:?} and requires ExportSecret policy on the registry",
                                variable.key, variable.sensitivity
                            );
                            continue;
                        }
                        if let Some(value) = variable
                            .current_version_id
                            .as_ref()
                            .and_then(|id| versions.iter().find(|version| &version.id == id))
                            .and_then(|version| version.plaintext_value.as_ref())
                        {
                            println!("{}={}", variable.key, shell_escape_env_value(value));
                        }
                    }
                }
                EnvCommand::Diff => {
                    println!(
                        "Local env diff shows masked metadata only; staged registry diffs are enforced by Nebula policy."
                    );
                    for variable in repo.list_environment_variables()? {
                        println!(
                            "{}\t{}\t{:?}\t{:?}",
                            variable.key,
                            variable.scope.stable_key(),
                            variable.availability,
                            variable.sensitivity
                        );
                    }
                }
            }
        }
        Command::Integration { command } => {
            let repo = open_repo()?;
            match command {
                IntegrationCommand::Add { provider } => {
                    let integration = repo.add_integration(provider)?;
                    println!(
                        "Added integration {}\t{:?}",
                        integration.provider, integration.actor
                    );
                }
                IntegrationCommand::Configure { provider } => {
                    let integration = repo.add_integration(provider)?;
                    println!("Configured integration {}", integration.provider);
                }
                IntegrationCommand::Test { provider } => {
                    let found = repo
                        .list_integrations()?
                        .into_iter()
                        .any(|integration| integration.provider == provider);
                    if found {
                        println!("Integration {provider} is configured.");
                    } else {
                        bail!("integration `{provider}` is not configured");
                    }
                }
            }
        }
        Command::Projection { command } => {
            let repo = open_repo()?;
            let snapshot = repo.active_snapshot()?;
            let decisions = projection_decisions(&repo, &snapshot)?;
            let environment = cli_environment(&snapshot, &environment_from_projection(&command));
            let target = target_from_projection(&command)?;
            let proposal = Proposal {
                id: ProposalId::generated(),
                repository_id: snapshot.repository_id.clone(),
                title: "local projection".to_string(),
                target_ref_id: RefId::generated(),
                changeset_ids: Vec::new(),
                state: ReviewState::Open,
                policy_checks: Vec::new(),
            };
            let plan = nebula_git::plan_git_projection(
                &snapshot,
                &proposal,
                nebula_git::GitProjectionRequest {
                    actor: Actor::Public,
                    environment,
                    target,
                    path_decisions: decisions,
                },
            )?;
            match command {
                ProjectionCommand::Preview { .. } => {
                    println!("Projection {}", plan.projection.id);
                    println!("included={}", plan.manifest.included_paths.len());
                    println!("redacted={}", plan.manifest.redacted_paths.len());
                    println!("templated={}", plan.manifest.templated_paths.len());
                    println!("omitted={}", plan.manifest.omitted_paths.len());
                    println!("blocked={}", plan.manifest.blocked_paths.len());
                }
                ProjectionCommand::Export {
                    environment,
                    target,
                } => {
                    let output_root = std::env::current_dir()?
                        .join(".nebula")
                        .join("exports")
                        .join(format!("{}-{}", environment, target));
                    let blobs = repo.blob_bytes_for_snapshot(&snapshot)?;
                    let materialized =
                        nebula_git::materialize_projection(&plan, &snapshot, &blobs, output_root)?;
                    println!(
                        "Exported projection to {} with {} file(s).",
                        materialized.root.display(),
                        materialized.written_paths.len()
                    );
                }
            }
        }
        Command::Ops {
            report_file,
            report_webhook,
            command,
        } => {
            let value = match command {
                OpsCommand::Migration => {
                    serde_json::to_value(nebula_storage::production_migration_plan(
                        nebula_storage::MetadataBackend::Postgres {
                            database_url: "$DATABASE_URL".to_string(),
                        },
                    ))?
                }
                OpsCommand::Consistency { command } => match command {
                    OpsConsistencyCommand::Check => {
                        serde_json::to_value(block_on_sync(consistency_report(false))?)?
                    }
                    OpsConsistencyCommand::Repair { execute } => {
                        serde_json::to_value(block_on_sync(consistency_report(execute))?)?
                    }
                },
                OpsCommand::Retention { command } => match command {
                    OpsRetentionCommand::Plan => {
                        serde_json::to_value(nebula_storage::default_retention_plan())?
                    }
                    OpsRetentionCommand::Cleanup { execute } => {
                        let plan = nebula_storage::default_retention_plan();
                        serde_json::to_value(block_on_sync(retention_cleanup_report(
                            plan, !execute,
                        ))?)?
                    }
                },
                OpsCommand::Backup { command } => match command {
                    OpsBackupCommand::Plan {
                        metadata_uri,
                        blob_uri,
                        vector_uri,
                    } => serde_json::to_value(nebula_storage::production_backup_plan(
                        metadata_uri,
                        blob_uri,
                        vector_uri,
                    ))?,
                    OpsBackupCommand::Drill {
                        tool,
                        execute,
                        operator,
                    } => serde_json::to_value(nebula_storage::backup_drill_report(
                        tool, !execute, operator,
                    ))?,
                },
                OpsCommand::Restore { command } => match command {
                    OpsRestoreCommand::Plan {
                        metadata_uri,
                        blob_uri,
                        vector_uri,
                    } => serde_json::to_value(nebula_storage::production_restore_plan(
                        metadata_uri,
                        blob_uri,
                        vector_uri,
                    ))?,
                    OpsRestoreCommand::Drill {
                        target,
                        backup_id,
                        tool,
                        execute,
                        operator,
                    } => serde_json::to_value(nebula_storage::restore_drill_report(
                        tool, target, backup_id, !execute, operator,
                    ))?,
                },
                OpsCommand::Registry { command } => match command {
                    OpsRegistryCommand::ImportFile {
                        source,
                        source_blob_store,
                        dry_run,
                        run_migrations,
                    } => {
                        let database_url = std::env::var("DATABASE_URL").context(
                            "DATABASE_URL is required for registry import (Postgres metadata)",
                        )?;
                        let blob_store_url = std::env::var("BLOB_STORE_URL").context(
                            "BLOB_STORE_URL is required for registry import (object store)",
                        )?;
                        let report = block_on_sync(async {
                            nebula_registry::import_persisted_registry(
                                nebula_registry::ImportFileOptions {
                                    source_path: source,
                                    database_url,
                                    blob_store_url,
                                    source_blob_store_path: source_blob_store,
                                    dry_run,
                                    run_migrations,
                                },
                            )
                            .await
                            .map_err(|error| anyhow::anyhow!(error))
                        })?;
                        serde_json::to_value(report)?
                    }
                },
            };
            emit_ops_report(&value, report_file.as_deref(), report_webhook.as_deref())?;
        }
        Command::Galaxy { command } => handle_galaxy_command(command, output)?,
        Command::Completions { shell } => {
            let mut command = NebCli::command();
            let name = command.get_name().to_string();
            clap_complete::generate(shell, &mut command, name, &mut std::io::stdout());
        }
        Command::Man => {
            let command = NebCli::command();
            clap_mangen::Man::new(command).render(&mut std::io::stdout())?;
        }
    }
    Ok(())
}

fn environment_from_projection(command: &ProjectionCommand) -> String {
    match command {
        ProjectionCommand::Preview { environment, .. }
        | ProjectionCommand::Export { environment, .. } => environment.clone(),
    }
}

fn target_from_projection(command: &ProjectionCommand) -> Result<ProjectionTarget> {
    let raw = match command {
        ProjectionCommand::Preview { target, .. } | ProjectionCommand::Export { target, .. } => {
            target.as_str()
        }
    };
    match raw {
        "github" => Ok(ProjectionTarget::GitHub),
        "vercel" => Ok(ProjectionTarget::Vercel),
        "local" => Ok(ProjectionTarget::Local),
        other if other.starts_with("ci:") => Ok(ProjectionTarget::Ci(other[3..].to_string())),
        other => Ok(ProjectionTarget::GitRemote(other.to_string())),
    }
}

fn cli_environment(snapshot: &nebula_core::TreeSnapshot, name: &str) -> Environment {
    let kind = match name {
        "development" => EnvironmentKind::Development,
        "staging" => EnvironmentKind::Staging,
        "production" => EnvironmentKind::Production,
        custom => EnvironmentKind::Custom(custom.to_string()),
    };
    Environment {
        id: EnvironmentId::new(format!("env_{name}")),
        repository_id: snapshot.repository_id.clone(),
        name: name.to_string(),
        kind,
    }
}

fn projection_decisions(
    repo: &LocalRepo,
    snapshot: &nebula_core::TreeSnapshot,
) -> Result<std::collections::BTreeMap<String, PolicyDecision>> {
    let mut decisions = std::collections::BTreeMap::new();
    for entry in &snapshot.entries {
        let evaluation = repo.check_policy(entry.path.clone(), PolicyAction::ExportGit)?;
        decisions.insert(entry.path.clone(), evaluation.decision);
    }
    Ok(decisions)
}

fn print_ref(reference: &nebula_core::Ref) {
    let target = match &reference.target {
        RefTarget::Snapshot(id) => format!("snapshot:{id}"),
        RefTarget::ChangeSet(id) => format!("changeset:{id}"),
        RefTarget::Proposal(id) => format!("proposal:{id}"),
    };
    println!("{}\t{}\t{}", reference.name, reference.id, target);
}

fn parse_policy_decision(raw: &str) -> Result<PolicyDecision> {
    match raw {
        "allow" => Ok(PolicyDecision::Allow),
        "redact" => Ok(PolicyDecision::Redact),
        "template" => Ok(PolicyDecision::Template),
        "omit" => Ok(PolicyDecision::Omit),
        "block" => Ok(PolicyDecision::Block),
        _ => bail!(
            "unknown policy decision `{raw}`; expected allow, redact, template, omit, or block"
        ),
    }
}

fn parse_policy_action(raw: &str) -> Result<PolicyAction> {
    match raw {
        "read_blob" => Ok(PolicyAction::ReadBlob),
        "read_path" => Ok(PolicyAction::ReadPath),
        "write_changeset" => Ok(PolicyAction::WriteChangeSet),
        "approve_changeset" => Ok(PolicyAction::ApproveChangeSet),
        "merge_changeset" => Ok(PolicyAction::MergeChangeSet),
        "export_git" => Ok(PolicyAction::ExportGit),
        "read_secret" => Ok(PolicyAction::ReadSecret),
        "inject_secret" => Ok(PolicyAction::InjectSecret),
        "read_build_source" => Ok(PolicyAction::ReadBuildSource),
        "create_projection" => Ok(PolicyAction::CreateProjection),
        "deploy" => Ok(PolicyAction::Deploy),
        "manage_variables" => Ok(PolicyAction::ManageVariables),
        "read_variable_metadata" => Ok(PolicyAction::ReadVariableMetadata),
        "read_encrypted_variable" => Ok(PolicyAction::ReadEncryptedVariable),
        "read_variable_value" => Ok(PolicyAction::ReadVariableValue),
        "inject_variable" => Ok(PolicyAction::InjectVariable),
        "reveal_variable" => Ok(PolicyAction::RevealVariable),
        "save_secret" => Ok(PolicyAction::SaveSecret),
        "push_secret" => Ok(PolicyAction::PushSecret),
        "export_secret" => Ok(PolicyAction::ExportSecret),
        "use_workspace_for_deploy" => Ok(PolicyAction::UseWorkspaceForDeploy),
        "mutate_deploy_variables" => Ok(PolicyAction::MutateDeployVariables),
        "manage_variable_policy" => Ok(PolicyAction::ManageVariablePolicy),
        _ => bail!("unknown policy action `{raw}`"),
    }
}

fn ensure_local_environment(repo: &LocalRepo, name: &str) -> Result<Environment> {
    if let Some(environment) = repo
        .list_environments()?
        .into_iter()
        .find(|environment| environment.name == name)
    {
        return Ok(environment);
    }
    repo.create_environment(name.to_string())
}

fn parse_variable_availability(raw: Vec<String>) -> Result<Vec<VariableAvailability>> {
    if raw.is_empty() {
        return Ok(vec![
            VariableAvailability::Build,
            VariableAvailability::Runtime,
        ]);
    }
    raw.into_iter()
        .map(|value| match value.as_str() {
            "build" => Ok(VariableAvailability::Build),
            "runtime" => Ok(VariableAvailability::Runtime),
            "functions" => Ok(VariableAvailability::Functions),
            "jobs" => Ok(VariableAvailability::Jobs),
            "local" => Ok(VariableAvailability::Local),
            other => bail!("unknown env variable scope `{other}`"),
        })
        .collect()
}

fn likely_secret_key(key: &str) -> bool {
    let key = key.to_ascii_uppercase();
    key.ends_with("_SECRET")
        || key.ends_with("_TOKEN")
        || key.ends_with("_PRIVATE_KEY")
        || key.contains("DATABASE_URL")
        || key.contains("API_KEY")
        || key.contains("PASSWORD")
        || key.contains("CREDENTIAL")
}

fn local_fingerprint(key: &str, value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"nebula-local-env-fingerprint");
    hasher.update(key.as_bytes());
    hasher.update(b"\0");
    hasher.update(value.as_bytes());
    hex::encode(hasher.finalize())
}

fn masked_fingerprint(sensitivity: &VariableSensitivity, fingerprint: &str) -> String {
    let suffix = fingerprint
        .get(fingerprint.len().saturating_sub(8)..)
        .unwrap_or(fingerprint);
    match sensitivity {
        VariableSensitivity::Public => "[public]".to_string(),
        VariableSensitivity::Encrypted => format!("[encrypted] ...{suffix}"),
        VariableSensitivity::Sensitive => format!("[sensitive] ...{suffix}"),
        VariableSensitivity::Sealed => format!("[sealed] ...{suffix}"),
    }
}

fn shell_escape_env_value(value: &str) -> String {
    if value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | '/' | ':'))
    {
        return value.to_string();
    }
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or_default()
}

fn parse_lfs_strategy(raw: &str) -> Result<nebula_git::GitLfsStrategy> {
    match raw {
        "pointers" => Ok(nebula_git::GitLfsStrategy::Pointers),
        "download" => Ok(nebula_git::GitLfsStrategy::Download),
        _ => bail!("unknown LFS strategy `{raw}`; expected pointers or download"),
    }
}

fn git_migration_source(repo: &str, mirror_path: Option<&str>) -> Result<std::path::PathBuf> {
    let repo_path = std::path::PathBuf::from(repo);
    if repo_path.exists() {
        return Ok(repo_path);
    }
    let Some(mirror_path) = mirror_path else {
        bail!(
            "Git migration source `{repo}` is not a local Git repo; pass --mirror-path to create/use a mirror cache"
        );
    };
    let mirror_path = std::path::PathBuf::from(mirror_path);
    if !mirror_path.exists() {
        nebula_git::execute_git_import(repo.to_string(), &mirror_path)?;
    }
    Ok(mirror_path)
}

fn migration_bundle(
    default_ref: String,
    migration: nebula_git::GitMigrationOutput,
) -> LocalSyncBundle {
    LocalSyncBundle {
        repository_id: migration.repository_id,
        default_ref,
        refs: migration
            .refs
            .into_iter()
            .map(|mapping| mapping.nebula_ref)
            .collect(),
        snapshots: migration.snapshots,
        changesets: Vec::new(),
        proposals: Vec::new(),
        operations: Vec::new(),
        git_migration_records: migration.migration_records,
        environment_variables: Vec::new(),
        environment_variable_versions: Vec::new(),
        environments: Vec::new(),
        blobs: migration
            .blobs
            .into_iter()
            .map(|blob| LocalBlobRecord {
                blob: blob.blob,
                bytes: blob.bytes,
            })
            .collect(),
    }
}

fn open_repo() -> Result<LocalRepo> {
    LocalRepo::open(std::env::current_dir()?)
}

fn remote_full_url(repo: &LocalRepo, remote_name: Option<String>) -> Option<String> {
    if let Some(remote) = &remote_name
        && is_registry_remote(remote)
    {
        return Some(remote.clone());
    }
    let name = remote_name.unwrap_or_else(|| "origin".to_string());
    repo.list_remotes()
        .ok()?
        .into_iter()
        .find(|r| r.name == name)
        .map(|r| r.url)
}

fn remote_registry_url(repo: &LocalRepo, remote_name: Option<String>) -> Result<Option<String>> {
    if let Some(remote) = &remote_name
        && is_registry_remote(remote)
    {
        return Ok(Some(registry_base_url(remote)));
    }
    let name = remote_name.unwrap_or_else(|| "origin".to_string());
    let remote = repo
        .list_remotes()?
        .into_iter()
        .find(|remote| remote.name == name);
    Ok(remote
        .map(|remote| remote.url)
        .filter(|url| is_registry_remote(url))
        .map(|url| registry_base_url(&url)))
}

fn registry_remote_url(repo: &LocalRepo, remote_name: &str) -> Result<String> {
    remote_registry_url(repo, Some(remote_name.to_string()))?.ok_or_else(|| {
        anyhow::anyhow!(
            "remote `{remote_name}` is not a Nebula registry remote; add one with `neb remote add {remote_name} <registry-url>`"
        )
    })
}

struct ParsedRegistryRemote {
    registry_url: String,
    repository_id: nebula_core::RepositoryId,
    remote_url: String,
}

fn parse_registry_clone_remote(remote: &str) -> Option<ParsedRegistryRemote> {
    if let Some((url, repository_id)) = remote.split_once('#')
        && is_registry_remote(url)
        && !repository_id.trim().is_empty()
    {
        return Some(ParsedRegistryRemote {
            registry_url: registry_base_url(url),
            repository_id: nebula_core::RepositoryId::new(repository_id),
            remote_url: remote.to_string(),
        });
    }

    if let Some(parsed) = parse_neb_remote_url(remote) {
        return Some(parsed);
    }

    if let Some(galaxy) = parse_named_galaxy_url(remote) {
        let token = auth_token_for_registry(&galaxy.registry_url).ok();
        let repository_id = block_on_sync(resolve_named_galaxy(
            &galaxy.registry_url,
            &galaxy.owner,
            &galaxy.name,
            token.as_deref(),
        ))
        .ok()?;
        return Some(ParsedRegistryRemote {
            registry_url: galaxy.registry_url,
            repository_id,
            remote_url: galaxy.remote_url,
        });
    }

    None
}

fn parse_neb_remote_url(remote: &str) -> Option<ParsedRegistryRemote> {
    if !is_registry_remote(remote) {
        return None;
    }
    let without_query = remote.split(['?', '#']).next()?;
    let (base_url, name) = without_query.rsplit_once('/')?;
    let repository_id = name.strip_suffix(".neb")?.trim();
    if repository_id.is_empty() || !repository_id.starts_with("repo_") {
        return None;
    }
    Some(ParsedRegistryRemote {
        registry_url: base_url.to_string(),
        repository_id: nebula_core::RepositoryId::new(repository_id),
        remote_url: remote.to_string(),
    })
}

struct ParsedGalaxyName {
    registry_url: String,
    owner: String,
    name: String,
    remote_url: String,
}

fn parse_named_galaxy_url(remote: &str) -> Option<ParsedGalaxyName> {
    if !is_registry_remote(remote) {
        return None;
    }
    let without_query = remote.split(['?', '#']).next()?;
    let (base_url, slug) = without_query.rsplit_once('/')?;
    let name = slug.strip_suffix(".neb")?.trim();
    if name.is_empty() || name.starts_with("repo_") {
        return None;
    }
    let (registry_url, owner) = base_url.rsplit_once('/')?;
    if !is_registry_remote(registry_url) {
        return None;
    }
    Some(ParsedGalaxyName {
        registry_url: registry_url.to_string(),
        owner: owner.to_string(),
        name: name.to_string(),
        remote_url: remote.to_string(),
    })
}

async fn resolve_named_galaxy(
    registry_url: &str,
    owner: &str,
    name: &str,
    token: Option<&str>,
) -> anyhow::Result<nebula_core::RepositoryId> {
    let url = format!("{}/v1/galaxies/by-name/{}/{}", registry_url, owner, name);
    let client = reqwest::Client::new();
    let mut req = client.get(&url);
    if let Some(t) = token {
        req = req.bearer_auth(t);
    }
    let resp = req.send().await?;
    if !resp.status().is_success() {
        return Err(anyhow::anyhow!("galaxy not found: {}/{}", owner, name));
    }
    let record: serde_json::Value = resp.json().await?;
    let id = record["id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("invalid response"))?;
    Ok(nebula_core::RepositoryId::new(id))
}

fn registry_base_url(remote: &str) -> String {
    if let Some(parsed) = parse_neb_remote_url(remote) {
        return parsed.registry_url;
    }
    if let Some(galaxy) = parse_named_galaxy_url(remote) {
        return galaxy.registry_url;
    }
    remote.trim_end_matches('/').to_string()
}

fn handle_auth_command(command: AuthCommand, output: CliOutput) -> Result<()> {
    match command {
        AuthCommand::Register {
            registry_url,
            remote,
            email,
            name,
            password,
        } => {
            let registry_url = resolve_auth_registry_url(registry_url, Some(remote))?;
            let email = email
                .or_else(|| prompt_input("Email: ").ok())
                .ok_or_else(|| anyhow::anyhow!("email is required"))?;
            let name = name
                .or_else(|| prompt_input("Name: ").ok())
                .unwrap_or_else(|| email.split('@').next().unwrap_or("user").to_string());
            let password = password
                .or_else(|| prompt_password("Password: ").ok())
                .ok_or_else(|| anyhow::anyhow!("password is required"))?;
            let body = json!({ "email": email, "password": password, "name": name });
            let response: serde_json::Value = block_on_sync(async {
                auth_request(
                    reqwest::Client::new()
                        .post(format!("{}/auth/sign-up/email", registry_url))
                        .json(&body),
                )
                .await?
                .json()
                .await
                .context("failed to decode sign-up response")
            })?;
            let token = response
                .get("token")
                .or_else(|| response.pointer("/session/token"))
                .and_then(|v| v.as_str())
                .map(str::to_string);
            if let Some(token) = token {
                let storage = auth::store_credential(auth::StoredCredential {
                    registry_url: registry_url.clone(),
                    token,
                    org_id: None,
                    repository_id: None,
                    scopes: vec![],
                })?;
                if output.json {
                    print_json(json!({ "ok": true, "registry_url": storage.registry_url }))?;
                } else if !output.quiet {
                    println!("Account created and logged in to {}.", registry_url);
                }
            } else if output.json {
                print_json(response)?;
            } else if !output.quiet {
                println!(
                    "Account created on {}. Run `neb auth login` to authenticate.",
                    registry_url
                );
            }
        }
        AuthCommand::Login {
            registry_url,
            remote,
            token,
            email,
            password,
            org,
            repository,
            scopes,
        } => {
            let registry_url = resolve_auth_registry_url(registry_url, Some(remote))?;
            let token = if let Some(t) = token.or_else(|| std::env::var("NEBULA_AUTH_TOKEN").ok()) {
                t
            } else if email.is_some() || password.is_some() {
                let email = email
                    .or_else(|| prompt_input("Email: ").ok())
                    .ok_or_else(|| anyhow::anyhow!("email is required"))?;
                let password = password
                    .or_else(|| prompt_password("Password: ").ok())
                    .ok_or_else(|| anyhow::anyhow!("password is required"))?;
                let body = json!({ "email": email, "password": password });
                let response: serde_json::Value = block_on_sync(async {
                    auth_request(
                        reqwest::Client::new()
                            .post(format!("{}/auth/sign-in/email", registry_url))
                            .json(&body),
                    )
                    .await?
                    .json()
                    .await
                    .context("failed to decode sign-in response")
                })?;
                response
                    .get("token")
                    .or_else(|| response.pointer("/session/token"))
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
                    .ok_or_else(|| anyhow::anyhow!("sign-in succeeded but no token in response; check the registry sign-in endpoint"))?
            } else {
                bail!(
                    "auth login requires --token, --email/--password, or NEBULA_AUTH_TOKEN\n\
                     To create an account: neb auth register --registry-url {registry_url}\n\
                     To use an API key:    neb auth token create from an existing session"
                )
            };
            let storage = auth::store_credential(auth::StoredCredential {
                registry_url: registry_url.clone(),
                token,
                org_id: org,
                repository_id: repository,
                scopes,
            })?;
            if let Err(err) = auth::load_credential(&registry_url) {
                eprintln!(
                    "Warning: credential was stored but could not be immediately retrieved: {err:#}"
                );
            }
            if output.json {
                print_json(json!({
                    "ok": true,
                    "registry_url": storage.registry_url,
                    "storage": storage.storage,
                }))?;
            } else if !output.quiet {
                println!(
                    "Stored Nebula registry credential for {} in {}.",
                    storage.registry_url, storage.storage
                );
            }
        }
        AuthCommand::Status {
            registry_url,
            remote,
        } => {
            if registry_url.is_none() && remote.is_none() {
                let credentials = auth::list_credentials()?;
                if output.json {
                    print_json(json!({ "credentials": credentials }))?;
                } else if credentials.is_empty() {
                    println!("No Nebula registry credentials are stored.");
                } else {
                    for credential in credentials {
                        println!(
                            "{}\tstorage={}\torg={}\trepository={}\tscopes={}",
                            credential.registry_url,
                            credential.storage,
                            credential.org_id.as_deref().unwrap_or("-"),
                            credential.repository_id.as_deref().unwrap_or("-"),
                            credential.scopes.join(",")
                        );
                    }
                }
                return Ok(());
            }
            let registry_url = resolve_auth_registry_url(registry_url, remote)?;
            let credential = auth::load_credential(&registry_url)?;
            if output.json {
                print_json(json!({
                    "registry_url": registry_url,
                    "authenticated": credential.is_some(),
                }))?;
            } else if let Some(credential) = credential {
                println!(
                    "Authenticated for {} (org={}, repository={}, scopes={}).",
                    credential.registry_url,
                    credential.org_id.as_deref().unwrap_or("-"),
                    credential.repository_id.as_deref().unwrap_or("-"),
                    credential.scopes.join(",")
                );
            } else {
                println!("No stored credential for {registry_url}.");
            }
        }
        AuthCommand::Logout {
            registry_url,
            remote,
        } => {
            let registry_url = resolve_auth_registry_url(registry_url, Some(remote))?;
            let deleted = auth::delete_credential(&registry_url)?;
            if output.json {
                print_json(json!({
                    "ok": true,
                    "registry_url": registry_url,
                    "deleted": deleted,
                }))?;
            } else if deleted {
                println!("Removed Nebula registry credential for {registry_url}.");
            } else {
                println!("No stored credential existed for {registry_url}.");
            }
        }
        AuthCommand::Token { command } => handle_auth_token_command(command, output)?,
        AuthCommand::Whoami {
            registry_url,
            remote,
        } => {
            let registry_url = resolve_auth_registry_url(registry_url, Some(remote))?;
            let token = auth_token_for_registry(&registry_url)?;
            let response: serde_json::Value = block_on_sync(async {
                let resp = reqwest::Client::new()
                    .get(format!("{}/v1/whoami", registry_url))
                    .bearer_auth(&token)
                    .send()
                    .await
                    .context("failed to reach registry")?;
                let status = resp.status();
                if !status.is_success() {
                    let body = resp.text().await.unwrap_or_default();
                    bail!("registry returned {status}: {body}");
                }
                resp.json()
                    .await
                    .context("failed to decode whoami response")
            })?;
            if output.json {
                print_json(response)?;
            } else {
                let actor = response
                    .get("actor")
                    .map(format_actor_json)
                    .unwrap_or_default();
                let org_id = response
                    .get("org_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("-");
                let repository_id = response
                    .get("repository_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("(unbound - any repo you're authorized for)");
                let scopes = response
                    .get("scopes")
                    .and_then(|v| v.as_array())
                    .map(|scopes| {
                        scopes
                            .iter()
                            .filter_map(|s| s.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    })
                    .unwrap_or_default();
                let bypasses = response
                    .get("bypasses_policy_checks")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let token_id = response
                    .get("token_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("-");
                println!("actor:       {actor}");
                println!("token_id:    {token_id}");
                println!("org:         {org_id}");
                println!("repository:  {repository_id}");
                println!("scopes:      {scopes}");
                if bypasses {
                    println!(
                        "note:        this identity bypasses per-repository policy checks (ManageAuth)"
                    );
                } else {
                    println!(
                        "note:        use the actor value above with `neb galaxy policy grant` to authorize this identity for an action; add --token {token_id} to that command to scope the grant to just this token instead of the whole account"
                    );
                }
            }
        }
    }
    Ok(())
}

fn handle_auth_token_command(command: AuthTokenCommand, output: CliOutput) -> Result<()> {
    match command {
        AuthTokenCommand::Create {
            name,
            registry_url,
            remote,
            org,
            repository,
            scopes,
            expires_in_days,
        } => {
            let registry_url = resolve_auth_registry_url(registry_url, Some(remote))?;
            let token = auth_token_for_registry(&registry_url)?;
            let permissions = permissions_from_scopes(&scopes);
            let expires_in = expires_in_days.map(|days| days * 24 * 60 * 60 * 1000);
            let body = json!({
                "name": name,
                "expiresIn": expires_in,
                "permissions": permissions,
                "metadata": {
                    "org_id": org,
                    "repository_id": repository,
                }
            });
            let response: serde_json::Value = block_on_sync(async {
                auth_request(
                    reqwest::Client::new()
                        .post(format!("{}/auth/api-key/create", registry_url))
                        .bearer_auth(token)
                        .json(&body),
                )
                .await?
                .json()
                .await
                .context("failed to decode API-key creation response")
            })?;
            if output.json {
                print_json(response)?;
            } else {
                println!("Created Better Auth API key.");
                if let Some(raw_key) = response.get("key").and_then(|value| value.as_str()) {
                    println!("{raw_key}");
                    println!("Store this raw key now; Better Auth only returns it once.");
                }
            }
        }
        AuthTokenCommand::List {
            registry_url,
            remote,
        } => {
            let registry_url = resolve_auth_registry_url(registry_url, Some(remote))?;
            let token = auth_token_for_registry(&registry_url)?;
            let keys: serde_json::Value = block_on_sync(async {
                auth_request(
                    reqwest::Client::new()
                        .get(format!("{}/auth/api-key/list", registry_url))
                        .bearer_auth(token),
                )
                .await?
                .json()
                .await
                .context("failed to decode API-key list response")
            })?;
            if output.json {
                print_json(keys)?;
            } else if let Some(keys) = keys.as_array() {
                for key in keys {
                    println!(
                        "{}\t{}\tenabled={}",
                        key.get("id")
                            .and_then(|value| value.as_str())
                            .unwrap_or("-"),
                        key.get("name")
                            .and_then(|value| value.as_str())
                            .unwrap_or("-"),
                        key.get("enabled")
                            .and_then(|value| value.as_bool())
                            .unwrap_or(false)
                    );
                }
            } else {
                println!("{keys}");
            }
        }
        AuthTokenCommand::Revoke {
            id,
            registry_url,
            remote,
        } => {
            let registry_url = resolve_auth_registry_url(registry_url, Some(remote))?;
            let token = auth_token_for_registry(&registry_url)?;
            let body = json!({ "id": id });
            let response: serde_json::Value = block_on_sync(async {
                auth_request(
                    reqwest::Client::new()
                        .post(format!("{}/auth/api-key/delete", registry_url))
                        .bearer_auth(token)
                        .json(&body),
                )
                .await?
                .json()
                .await
                .context("failed to decode API-key revoke response")
            })?;
            if output.json {
                print_json(response)?;
            } else {
                println!("Revoked Better Auth API key {id}.");
            }
        }
    }
    Ok(())
}

fn resolve_auth_registry_url(
    registry_url: Option<String>,
    remote: Option<String>,
) -> Result<String> {
    if let Some(registry_url) = registry_url {
        if !is_registry_remote(&registry_url) {
            bail!("registry URL must start with http:// or https://");
        }
        return Ok(auth::normalize_registry_url(&registry_url));
    }
    let repo = open_repo()?;
    let remote = remote.unwrap_or_else(|| "origin".to_string());
    registry_remote_url(&repo, &remote).map(|url| auth::normalize_registry_url(&url))
}

fn auth_token_for_registry(registry_url: &str) -> Result<String> {
    if let Ok(token) = std::env::var("NEBULA_AUTH_TOKEN") {
        return Ok(token);
    }
    auth::load_credential(registry_url)?
        .map(|credential| credential.token)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no credential for {registry_url}; run `neb auth login --registry-url {registry_url} --token <token>`"
            )
        })
}

fn permissions_from_scopes(scopes: &[String]) -> serde_json::Value {
    let actions = if scopes.is_empty() {
        vec!["read_blob".to_string(), "sync_objects".to_string()]
    } else {
        scopes
            .iter()
            .map(|scope| {
                scope
                    .strip_prefix("nebula.repository:")
                    .unwrap_or(scope)
                    .to_string()
            })
            .collect()
    };
    json!({ "nebula.repository": actions })
}

async fn auth_request(request: reqwest::RequestBuilder) -> Result<reqwest::Response> {
    let response = request
        .send()
        .await
        .context("failed to reach Better Auth endpoint")?;
    let status = response.status();
    if status.is_success() {
        return Ok(response);
    }
    let body = response.text().await.unwrap_or_default();
    let message = serde_json::from_str::<AuthErrorBody>(&body)
        .ok()
        .and_then(|body| body.error.or(body.message).or(body.code))
        .filter(|message| !message.is_empty())
        .unwrap_or_else(|| body.trim().to_string());
    bail!(
        "Better Auth request failed with {status}: {}",
        if message.is_empty() {
            "no error body".to_string()
        } else {
            message
        }
    )
}

#[derive(Debug, Deserialize)]
struct AuthErrorBody {
    error: Option<String>,
    message: Option<String>,
    code: Option<String>,
}

fn sync_client(url: String) -> Result<RegistrySyncClient> {
    let url = registry_base_url(&url);
    let token = std::env::var("NEBULA_AUTH_TOKEN").ok().or_else(|| {
        auth::load_credential(&url)
            .ok()
            .flatten()
            .map(|credential| credential.token)
    });
    Ok(RegistrySyncClient::new(url, token))
}

async fn consistency_report(
    execute_repair: bool,
) -> Result<nebula_storage::ConsistencyCheckReport> {
    let database_url = std::env::var("DATABASE_URL")
        .map_err(|_| anyhow::anyhow!("DATABASE_URL is required for consistency checks"))?;
    let blob_store_url = std::env::var("BLOB_STORE_URL")
        .map_err(|_| anyhow::anyhow!("BLOB_STORE_URL is required for consistency checks"))?;
    let metadata = nebula_storage::PostgresMetadataStore::connect(&database_url).await?;
    let blob_store = nebula_storage::ObjectBlobStore::from_url(&blob_store_url)?;
    let required_hashes = metadata.required_blob_hashes().await?;
    let report = blob_store.consistency_report(&required_hashes).await?;
    let deleted_orphans = if execute_repair {
        blob_store.delete_orphaned_objects(&required_hashes).await?
    } else {
        0
    };
    Ok(nebula_storage::ConsistencyCheckReport {
        checked_at_unix_ms: current_unix_ms(),
        required_blob_count: required_hashes.len(),
        missing: report.missing,
        orphaned_paths: report.orphaned_paths,
        dry_run: !execute_repair,
        deleted_orphans,
    })
}

async fn retention_cleanup_report(
    plan: nebula_storage::RetentionPlan,
    dry_run: bool,
) -> Result<nebula_storage::RetentionCleanupReport> {
    let database_url = std::env::var("DATABASE_URL")
        .map_err(|_| anyhow::anyhow!("DATABASE_URL is required for retention cleanup"))?;
    let metadata = nebula_storage::PostgresMetadataStore::connect(&database_url).await?;
    Ok(metadata.retention_cleanup_report(plan, dry_run).await?)
}

fn prompt_input(label: &str) -> Result<String> {
    use std::io::Write;
    print!("{label}");
    std::io::stdout().flush()?;
    let mut buf = String::new();
    std::io::stdin().read_line(&mut buf)?;
    Ok(buf.trim().to_string())
}

fn prompt_password(label: &str) -> Result<String> {
    rpassword::prompt_password(label).context("failed to read password")
}

fn handle_galaxy_command(command: GalaxyCommand, output: CliOutput) -> Result<()> {
    match command {
        GalaxyCommand::Create {
            name,
            registry_url,
            remote,
            org,
        } => {
            let registry_url =
                resolve_auth_registry_url(Some(registry_url).flatten(), Some(remote))?;
            let token = auth_token_for_registry(&registry_url)?;
            let body = json!({ "name": name, "org_id": org });
            let response: serde_json::Value = block_on_sync(async {
                let resp = reqwest::Client::new()
                    .post(format!("{}/v1/galaxies", registry_url))
                    .bearer_auth(&token)
                    .json(&body)
                    .send()
                    .await
                    .context("failed to reach registry")?;
                let status = resp.status();
                if !status.is_success() {
                    let body = resp.text().await.unwrap_or_default();
                    bail!("registry returned {status}: {body}");
                }
                resp.json()
                    .await
                    .context("failed to decode repository response")
            })?;
            if output.json {
                print_json(response)?;
            } else {
                let id = response.get("id").and_then(|v| v.as_str()).unwrap_or("?");
                let name = response.get("name").and_then(|v| v.as_str()).unwrap_or("?");
                println!("Created galaxy {name} ({id}) on {registry_url}");
                println!("  neb remote add origin {registry_url}/{id}.neb");
                println!("  neb auth login --registry-url {registry_url} --token <your-token>");
                println!("  neb push origin");
            }
        }
        GalaxyCommand::DeployConfig { command } => handle_deploy_config_command(command, output)?,
        GalaxyCommand::Policy { command } => handle_galaxy_policy_command(command, output)?,
        GalaxyCommand::List {
            org,
            registry_url,
            remote,
        } => {
            let registry_url =
                resolve_auth_registry_url(Some(registry_url).flatten(), Some(remote))?;
            let token = auth_token_for_registry(&registry_url)?;
            let response: serde_json::Value = block_on_sync(async {
                let mut req = reqwest::Client::new()
                    .get(format!("{}/v1/galaxies", registry_url))
                    .bearer_auth(&token);
                if let Some(org) = &org {
                    req = req.query(&[("org_id", org)]);
                }
                let resp = req.send().await.context("failed to reach registry")?;
                let status = resp.status();
                if !status.is_success() {
                    let body = resp.text().await.unwrap_or_default();
                    bail!("registry returned {status}: {body}");
                }
                resp.json()
                    .await
                    .context("failed to decode galaxy list response")
            })?;
            if output.json {
                print_json(response)?;
            } else {
                let galaxies = response.as_array().cloned().unwrap_or_default();
                if galaxies.is_empty() {
                    println!("No galaxies found.");
                }
                for galaxy in galaxies {
                    let id = galaxy.get("id").and_then(|v| v.as_str()).unwrap_or("?");
                    let name = galaxy.get("name").and_then(|v| v.as_str()).unwrap_or("?");
                    let org_id = galaxy.get("org_id").and_then(|v| v.as_str()).unwrap_or("-");
                    println!("{id}\torg={org_id}\t{name}");
                }
            }
        }
        GalaxyCommand::Get {
            galaxy,
            registry_url,
            remote,
        } => {
            let registry_url =
                resolve_auth_registry_url(Some(registry_url).flatten(), Some(remote))?;
            let token = auth_token_for_registry(&registry_url)?;
            let response: serde_json::Value = block_on_sync(async {
                let galaxy_id = resolve_galaxy_id_async(&registry_url, &token, &galaxy).await?;
                let resp = reqwest::Client::new()
                    .get(format!("{}/v1/galaxies/{}", registry_url, galaxy_id))
                    .bearer_auth(&token)
                    .send()
                    .await
                    .context("failed to reach registry")?;
                let status = resp.status();
                if !status.is_success() {
                    let body = resp.text().await.unwrap_or_default();
                    bail!("registry returned {status}: {body}");
                }
                resp.json()
                    .await
                    .context("failed to decode galaxy response")
            })?;
            print_json(response)?;
        }
    }
    Ok(())
}

/// Converts a CLI action string ("manage_deploy_config", optionally prefixed
/// with "nebula.repository:") into the PascalCase form `PolicyAction` uses on
/// the wire (e.g. "ManageDeployConfig").
fn policy_action_json(action: &str) -> String {
    let stripped = action.strip_prefix("nebula.repository:").unwrap_or(action);
    stripped
        .split('_')
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect::<String>()
}

/// Parses a CLI actor spec ("public" or "<kind>:<id>") into the JSON shape
/// the registry's externally-tagged `Actor` enum expects.
fn parse_actor_json(actor: &str) -> Result<serde_json::Value> {
    if actor.eq_ignore_ascii_case("public") {
        return Ok(json!("Public"));
    }
    let (kind, id) = actor.split_once(':').ok_or_else(|| {
        anyhow::anyhow!(
            "actor must be \"public\" or \"<kind>:<id>\" (kind: user, team, agent, integration)"
        )
    })?;
    let key = match kind.to_ascii_lowercase().as_str() {
        "user" => "User",
        "team" => "Team",
        "agent" => "Agent",
        "integration" => "Integration",
        other => bail!("unknown actor kind '{other}'; expected user, team, agent, or integration"),
    };
    Ok(json!({ key: id }))
}

/// The inverse of `parse_actor_json`: formats the registry's wire-format
/// `Actor` JSON back into the CLI's "<kind>:<id>" spec, so a printed actor
/// (e.g. from `neb auth whoami` or `neb galaxy policy list`) can be pasted
/// directly into `neb galaxy policy grant`.
fn format_actor_json(actor: &serde_json::Value) -> String {
    if let Some(s) = actor.as_str() {
        return s.to_ascii_lowercase();
    }
    if let Some(obj) = actor.as_object()
        && let Some((kind, value)) = obj.iter().next()
        && let Some(id) = value.as_str()
    {
        return format!("{}:{}", kind.to_ascii_lowercase(), id);
    }
    actor.to_string()
}

fn handle_galaxy_policy_command(command: GalaxyPolicyCommand, output: CliOutput) -> Result<()> {
    match command {
        GalaxyPolicyCommand::Grant {
            galaxy,
            actor,
            actions,
            priority,
            reason,
            token_id: grant_token_id,
            registry_url,
            remote,
        } => {
            let actor_json = parse_actor_json(&actor)?;
            let action_values = actions
                .iter()
                .map(|action| policy_action_json(action))
                .collect::<Vec<_>>();
            let registry_url =
                resolve_auth_registry_url(Some(registry_url).flatten(), Some(remote))?;
            let token = auth_token_for_registry(&registry_url)?;
            let policy_id = nebula_core::PolicyId::generated();
            let policy_name = format!("grant-{actor}-{}", actions.join("-"));
            let response: serde_json::Value = block_on_sync(async {
                let galaxy_id = resolve_galaxy_id_async(&registry_url, &token, &galaxy).await?;
                let body = json!({
                    "id": policy_id.as_str(),
                    "repository_id": galaxy_id,
                    "name": policy_name,
                    "priority": priority,
                    "rules": [{
                        "actor": actor_json,
                        "token_id": grant_token_id,
                        "environment_id": null,
                        "environment_kind": null,
                        "path_glob": null,
                        "key_glob": null,
                        "service_id": null,
                        "workspace_id": null,
                        "sensitivity": null,
                        "availability": null,
                        "actions": action_values,
                        "decision": "Allow",
                        "reason": reason,
                    }],
                });
                let resp = reqwest::Client::new()
                    .put(format!(
                        "{}/v1/galaxies/{}/policies",
                        registry_url, galaxy_id
                    ))
                    .bearer_auth(&token)
                    .json(&body)
                    .send()
                    .await
                    .context("failed to reach registry")?;
                let status = resp.status();
                if !status.is_success() {
                    let body = resp.text().await.unwrap_or_default();
                    bail!("registry returned {status}: {body}");
                }
                resp.json()
                    .await
                    .context("failed to decode policy response")
            })?;
            if output.json {
                print_json(response)?;
            } else {
                match &grant_token_id {
                    Some(token_id) => println!(
                        "Granted {} to {} (token {token_id} only) on {} (policy {})",
                        actions.join(", "),
                        actor,
                        galaxy,
                        policy_id.as_str()
                    ),
                    None => println!(
                        "Granted {} to {} on {} (policy {})",
                        actions.join(", "),
                        actor,
                        galaxy,
                        policy_id.as_str()
                    ),
                }
            }
        }
        GalaxyPolicyCommand::List {
            galaxy,
            registry_url,
            remote,
        } => {
            let registry_url =
                resolve_auth_registry_url(Some(registry_url).flatten(), Some(remote))?;
            let token = auth_token_for_registry(&registry_url)?;
            let response: serde_json::Value = block_on_sync(async {
                let galaxy_id = resolve_galaxy_id_async(&registry_url, &token, &galaxy).await?;
                let resp = reqwest::Client::new()
                    .get(format!(
                        "{}/v1/galaxies/{}/policies",
                        registry_url, galaxy_id
                    ))
                    .bearer_auth(&token)
                    .send()
                    .await
                    .context("failed to reach registry")?;
                let status = resp.status();
                if !status.is_success() {
                    let body = resp.text().await.unwrap_or_default();
                    bail!("registry returned {status}: {body}");
                }
                resp.json()
                    .await
                    .context("failed to decode policy list response")
            })?;
            if output.json {
                print_json(response)?;
            } else {
                let policies = response.as_array().cloned().unwrap_or_default();
                if policies.is_empty() {
                    println!("No policies granted on {galaxy}.");
                }
                for policy in policies {
                    let id = policy.get("id").and_then(|v| v.as_str()).unwrap_or("?");
                    let name = policy.get("name").and_then(|v| v.as_str()).unwrap_or("?");
                    let priority = policy.get("priority").and_then(|v| v.as_i64()).unwrap_or(0);
                    println!("{id}\tpriority={priority}\t{name}");
                    for rule in policy
                        .get("rules")
                        .and_then(|v| v.as_array())
                        .into_iter()
                        .flatten()
                    {
                        let actor = rule.get("actor").map(format_actor_json).unwrap_or_default();
                        let actions = rule
                            .get("actions")
                            .and_then(|v| v.as_array())
                            .map(|actions| {
                                actions
                                    .iter()
                                    .filter_map(|a| a.as_str())
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            })
                            .unwrap_or_default();
                        let decision = rule.get("decision").cloned().unwrap_or_default();
                        let token_suffix = rule
                            .get("token_id")
                            .and_then(|v| v.as_str())
                            .map(|token_id| format!("\ttoken={token_id}"))
                            .unwrap_or_default();
                        println!(
                            "    actor={actor}\tdecision={decision}\tactions=[{actions}]{token_suffix}"
                        );
                    }
                }
            }
        }
        GalaxyPolicyCommand::Revoke {
            galaxy,
            policy_id,
            registry_url,
            remote,
        } => {
            let registry_url =
                resolve_auth_registry_url(Some(registry_url).flatten(), Some(remote))?;
            let token = auth_token_for_registry(&registry_url)?;
            block_on_sync(async {
                let galaxy_id = resolve_galaxy_id_async(&registry_url, &token, &galaxy).await?;
                let resp = reqwest::Client::new()
                    .delete(format!(
                        "{}/v1/galaxies/{}/policies/{}",
                        registry_url, galaxy_id, policy_id
                    ))
                    .bearer_auth(&token)
                    .send()
                    .await
                    .context("failed to reach registry")?;
                let status = resp.status();
                if !status.is_success() {
                    let body = resp.text().await.unwrap_or_default();
                    bail!("registry returned {status}: {body}");
                }
                Ok(())
            })?;
            if output.json {
                print_json(json!({ "ok": true, "policy_id": policy_id }))?;
            } else {
                println!("Revoked policy {policy_id} on {galaxy}");
            }
        }
    }
    Ok(())
}

/// Resolves `galaxy` to a `repo_...` id, looking it up by `owner/name` against
/// the registry if it isn't already an id. Must run inside the same
/// single-threaded runtime as the rest of the command (nested `block_on_sync`
/// calls would deadlock), so callers await this directly.
async fn resolve_galaxy_id_async(
    registry_url: &str,
    token: &str,
    galaxy: &str,
) -> anyhow::Result<String> {
    if galaxy.starts_with("repo_") {
        return Ok(galaxy.to_string());
    }
    let (owner, name) = galaxy
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("galaxy must be a repo_... id or owner/name"))?;
    let id = resolve_named_galaxy(registry_url, owner, name, Some(token)).await?;
    Ok(id.as_str().to_string())
}

fn handle_deploy_config_command(command: DeployConfigCommand, output: CliOutput) -> Result<()> {
    match command {
        DeployConfigCommand::Set {
            galaxy,
            service_id,
            deploy_url,
            signing_secret,
            provider_key,
            environment_id,
            environment_name,
            context_path,
            auto_deploy,
            registry_url,
            remote,
        } => {
            if signing_secret.len() < 16 {
                bail!("signing_secret must be at least 16 characters");
            }
            let registry_url =
                resolve_auth_registry_url(Some(registry_url).flatten(), Some(remote))?;
            let token = auth_token_for_registry(&registry_url)?;
            let body = json!({
                "provider_key": provider_key,
                "deploy_url": deploy_url,
                "signing_secret": signing_secret,
                "service_id": service_id,
                "environment_id": environment_id,
                "environment_name": environment_name,
                "context_path": context_path,
                "auto_deploy": auto_deploy,
            });
            let response: serde_json::Value = block_on_sync(async {
                let galaxy_id = resolve_galaxy_id_async(&registry_url, &token, &galaxy).await?;
                let resp = reqwest::Client::new()
                    .put(format!(
                        "{}/v1/galaxies/{}/deploy-configs/{}",
                        registry_url, galaxy_id, service_id
                    ))
                    .bearer_auth(&token)
                    .json(&body)
                    .send()
                    .await
                    .context("failed to reach registry")?;
                let status = resp.status();
                if !status.is_success() {
                    let body = resp.text().await.unwrap_or_default();
                    bail!("registry returned {status}: {body}");
                }
                resp.json()
                    .await
                    .context("failed to decode deploy config response")
            })?;
            if output.json {
                print_json(response)?;
            } else {
                println!("Set deploy config for {galaxy}/{service_id} on {registry_url}");
            }
        }
        DeployConfigCommand::Get {
            galaxy,
            service_id,
            registry_url,
            remote,
        } => {
            let registry_url =
                resolve_auth_registry_url(Some(registry_url).flatten(), Some(remote))?;
            let token = auth_token_for_registry(&registry_url)?;
            let response: serde_json::Value = block_on_sync(async {
                let galaxy_id = resolve_galaxy_id_async(&registry_url, &token, &galaxy).await?;
                let resp = reqwest::Client::new()
                    .get(format!(
                        "{}/v1/galaxies/{}/deploy-configs/{}",
                        registry_url, galaxy_id, service_id
                    ))
                    .bearer_auth(&token)
                    .send()
                    .await
                    .context("failed to reach registry")?;
                let status = resp.status();
                if !status.is_success() {
                    let body = resp.text().await.unwrap_or_default();
                    bail!("registry returned {status}: {body}");
                }
                resp.json()
                    .await
                    .context("failed to decode deploy config response")
            })?;
            print_json(response)?;
        }
        DeployConfigCommand::Delete {
            galaxy,
            service_id,
            registry_url,
            remote,
        } => {
            let registry_url =
                resolve_auth_registry_url(Some(registry_url).flatten(), Some(remote))?;
            let token = auth_token_for_registry(&registry_url)?;
            block_on_sync(async {
                let galaxy_id = resolve_galaxy_id_async(&registry_url, &token, &galaxy).await?;
                let resp = reqwest::Client::new()
                    .delete(format!(
                        "{}/v1/galaxies/{}/deploy-configs/{}",
                        registry_url, galaxy_id, service_id
                    ))
                    .bearer_auth(&token)
                    .send()
                    .await
                    .context("failed to reach registry")?;
                let status = resp.status();
                if !status.is_success() {
                    let body = resp.text().await.unwrap_or_default();
                    bail!("registry returned {status}: {body}");
                }
                Ok(())
            })?;
            if output.json {
                print_json(json!({ "ok": true, "galaxy": galaxy, "service_id": service_id }))?;
            } else {
                println!("Deleted deploy config for {galaxy}/{service_id}");
            }
        }
    }
    Ok(())
}

fn block_on_sync<T>(future: impl std::future::Future<Output = Result<T>>) -> Result<T> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(future)
}

fn print_json(value: serde_json::Value) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

fn emit_ops_report(
    value: &serde_json::Value,
    report_file: Option<&std::path::Path>,
    report_webhook: Option<&str>,
) -> Result<()> {
    let pretty = serde_json::to_string_pretty(value)?;
    println!("{pretty}");
    if let Some(path) = report_file {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, format!("{pretty}\n"))?;
    }
    if let Some(url) = report_webhook {
        block_on_sync(post_ops_report(url, value))?;
    }
    Ok(())
}

async fn post_ops_report(url: &str, value: &serde_json::Value) -> Result<()> {
    let body = serde_json::to_string(value)?;
    let sent_at = current_unix_ms();
    let mut request = reqwest::Client::new()
        .post(url)
        .header("content-type", "application/json")
        .header("x-nebula-sent-at", sent_at.to_string());
    if let Ok(secret) = std::env::var("NEBULA_TELEMETRY_WEBHOOK_SECRET") {
        let digest = sha256_hex(&format!("{secret}:ops-report:{sent_at}:{body}"));
        request = request.header("x-nebula-signature", format!("sha256:{digest}"));
    }
    request.body(body).send().await?.error_for_status()?;
    Ok(())
}

fn sha256_hex(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    hex::encode(hasher.finalize())
}

fn current_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or_default()
}

fn progress_spinner(output: CliOutput, message: &'static str) -> Option<ProgressBar> {
    if output.json || output.quiet {
        return None;
    }
    let spinner = ProgressBar::new_spinner();
    if let Ok(style) = ProgressStyle::with_template("{spinner:.green} {msg}") {
        spinner.set_style(style);
    }
    spinner.set_message(message);
    spinner.enable_steady_tick(std::time::Duration::from_millis(100));
    Some(spinner)
}

fn finish_progress(progress: Option<ProgressBar>, message: &'static str) {
    if let Some(progress) = progress {
        progress.finish_with_message(message);
    }
}

fn repo_path_hint(_repo: &LocalRepo) -> String {
    ".nebula".to_string()
}

fn truncate_path(path: &std::path::Path, max_len: usize) -> String {
    let s = path.to_string_lossy();
    if let Ok(home) = std::env::var("HOME")
        && s.starts_with(&home)
    {
        let rel = &s[home.len()..];
        let short = format!("~{rel}");
        if short.len() <= max_len {
            return short;
        }
        return format!("…{}", &short[short.len().saturating_sub(max_len)..]);
    }
    if s.len() <= max_len {
        return s.to_string();
    }
    format!("…{}", &s[s.len().saturating_sub(max_len)..])
}

fn print_repo_header(output: &CliOutput, repo: &LocalRepo, change_count: usize) {
    if output.json || output.quiet {
        return;
    }

    let version = env!("CARGO_PKG_VERSION");
    let cwd = std::env::current_dir().unwrap_or_else(|_| repo.root().to_path_buf());
    let path = truncate_path(&cwd, 42);
    let ref_name = repo
        .config()
        .ok()
        .map(|c| c.default_ref)
        .unwrap_or_else(|| "main".to_string());

    if output.no_color {
        println!("◆ v{version}  {path}  ⎇ {ref_name}  ± {change_count}");
        println!();
        return;
    }

    // 256-color ANSI: dark charcoal background, muted silver text
    let bg = "\x1b[48;5;235m";
    let fg = "\x1b[38;5;250m";
    let fg_accent = "\x1b[38;5;255m\x1b[1m";
    let reset = "\x1b[0m";
    let sep = format!("{reset}\x1b[38;5;240m  {reset}");

    let v_pill = format!("{bg}{fg} ◆ {fg_accent}v{version}{fg} {reset}");
    let p_pill = format!("{bg}{fg} {path} {reset}");
    let r_pill = format!("{bg}{fg} ⎇  {fg_accent}{ref_name}{fg} {reset}");
    let c_pill = format!("{bg}{fg} ± {fg_accent}{change_count}{fg} {reset}");

    println!("{v_pill}{sep}{p_pill}{sep}{r_pill}{sep}{c_pill}");
    println!();
}

fn print_diff_summary(diff: &nebula_core::TreeDiff) {
    if diff.entries.is_empty() {
        println!("No changes.");
        return;
    }
    let added = diff
        .entries
        .iter()
        .filter(|entry| matches!(entry.kind, TreeDiffKind::Added))
        .count();
    let modified = diff
        .entries
        .iter()
        .filter(|entry| matches!(entry.kind, TreeDiffKind::Modified))
        .count();
    let deleted = diff
        .entries
        .iter()
        .filter(|entry| matches!(entry.kind, TreeDiffKind::Deleted))
        .count();
    println!("{added} added, {modified} modified, {deleted} deleted");
}

fn print_diff_entries(entries: &[nebula_core::TreeDiffEntry]) {
    if entries.is_empty() {
        println!("No changes.");
        return;
    }
    for entry in entries {
        let marker = match entry.kind {
            TreeDiffKind::Added => "A",
            TreeDiffKind::Modified => "M",
            TreeDiffKind::Deleted => "D",
        };
        println!("{marker}\t{}", entry.path);
    }
}
