//! One-shot import of a file-backed `registry.json` into Postgres + object store.

use crate::{PersistedRegistry, StoredCedarPolicyDocument, blob_id, oci_manifest_id, ref_id};
use nebula_core::*;
use nebula_storage::{ObjectBlobStore, PostgresMetadataStore};
use serde::Serialize;
use std::{
    fs,
    path::{Path, PathBuf},
};
use tracing::info;

#[derive(Clone, Debug, Default, Serialize)]
pub struct ImportFileReport {
    pub dry_run: bool,
    pub source_path: String,
    pub repositories: usize,
    pub content_blobs: usize,
    pub content_blob_bytes_uploaded: usize,
    pub oci_blobs: usize,
    pub oci_blob_bytes_uploaded: usize,
    pub oci_manifests: usize,
    pub oci_tags: usize,
    pub other_resources: usize,
    pub source_blob_store_files_seen: usize,
    pub source_blob_store_files_copied: usize,
    pub skipped_existing_object_store_blobs: usize,
    pub errors: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct ImportFileOptions {
    pub source_path: PathBuf,
    pub database_url: String,
    pub blob_store_url: String,
    pub source_blob_store_path: Option<PathBuf>,
    pub dry_run: bool,
    pub run_migrations: bool,
}

pub async fn import_persisted_registry(
    options: ImportFileOptions,
) -> Result<ImportFileReport, String> {
    let content = fs::read_to_string(&options.source_path).map_err(|error| {
        format!(
            "failed to read {}: {error}",
            options.source_path.display()
        )
    })?;
    let persisted: PersistedRegistry = serde_json::from_str(&content).map_err(|error| {
        format!(
            "failed to parse {}: {error}",
            options.source_path.display()
        )
    })?;

    let mut report = ImportFileReport {
        dry_run: options.dry_run,
        source_path: options.source_path.display().to_string(),
        repositories: persisted.repositories.len(),
        content_blobs: persisted.blobs.len(),
        oci_blobs: persisted.oci_blobs.len(),
        oci_manifests: persisted.oci_manifests.len(),
        oci_tags: persisted.oci_tags.len(),
        ..ImportFileReport::default()
    };
    report.dry_run = options.dry_run;

    if options.dry_run {
        report.content_blob_bytes_uploaded = persisted
            .blobs
            .iter()
            .filter(|entry| !entry.bytes.is_empty())
            .count();
        report.oci_blob_bytes_uploaded = persisted
            .oci_blobs
            .iter()
            .filter(|entry| !entry.bytes.is_empty())
            .count();
        if let Some(source) = &options.source_blob_store_path {
            report.source_blob_store_files_seen = count_blob_store_files(source);
        }
        report.other_resources = count_other_resources(&persisted);
        return Ok(report);
    }

    let metadata = PostgresMetadataStore::connect(&options.database_url)
        .await
        .map_err(|error| error.to_string())?;
    if options.run_migrations {
        metadata
            .run_migrations()
            .await
            .map_err(|error| error.to_string())?;
    }
    let blob_store =
        ObjectBlobStore::from_url(&options.blob_store_url).map_err(|error| error.to_string())?;

    for entry in &persisted.blobs {
        put_resource(
            &metadata,
            None,
            "blob",
            &blob_id(&entry.blob.hash),
            &entry.blob,
        )
        .await?;
        if !entry.bytes.is_empty() {
            match upload_bytes(&blob_store, &entry.blob.hash, &entry.bytes, &mut report).await {
                Ok(uploaded) => {
                    if uploaded {
                        report.content_blob_bytes_uploaded += 1;
                    }
                }
                Err(error) => report.errors.push(error),
            }
        }
    }

    for entry in &persisted.oci_blobs {
        put_resource(&metadata, None, "oci_blob", &entry.blob.digest, &entry.blob).await?;
        if !entry.bytes.is_empty() {
            let Some(hash) = content_hash_from_digest(&entry.blob.digest) else {
                report.errors.push(format!(
                    "skip oci blob with unsupported digest {}",
                    entry.blob.digest
                ));
                continue;
            };
            match upload_bytes(&blob_store, &hash, &entry.bytes, &mut report).await {
                Ok(uploaded) => {
                    if uploaded {
                        report.oci_blob_bytes_uploaded += 1;
                    }
                }
                Err(error) => report.errors.push(error),
            }
        }
    }

    for repository in &persisted.repositories {
        put_resource(
            &metadata,
            Some(&repository.id),
            "repository",
            repository.id.as_str(),
            repository,
        )
        .await?;
    }

    for manifest in &persisted.oci_manifests {
        let id = oci_manifest_id(&manifest.repository_name_normalized, &manifest.digest);
        put_resource(&metadata, None, "oci_manifest", &id, manifest).await?;
    }

    for tag in &persisted.oci_tags {
        let id = format!("{}:{}", tag.repository_name_normalized, tag.tag);
        put_resource(&metadata, None, "oci_tag", &id, tag).await?;
    }

    for session in &persisted.oci_upload_sessions {
        put_resource(
            &metadata,
            None,
            "oci_upload_session",
            &session.uuid,
            session,
        )
        .await?;
    }

    for provenance in &persisted.oci_provenance {
        put_resource(
            &metadata,
            None,
            "oci_provenance",
            &provenance.manifest_digest,
            provenance,
        )
        .await?;
    }

    report.other_resources += import_protocol_resources(&metadata, &persisted).await?;

    if let Some(source) = &options.source_blob_store_path {
        let (seen, copied) =
            copy_source_blob_store(source, &blob_store, &mut report).await?;
        report.source_blob_store_files_seen = seen;
        report.source_blob_store_files_copied = copied;
    }

    info!(
        repositories = report.repositories,
        oci_manifests = report.oci_manifests,
        oci_tags = report.oci_tags,
        errors = report.errors.len(),
        "finished registry file import"
    );
    Ok(report)
}

async fn import_protocol_resources(
    metadata: &PostgresMetadataStore,
    persisted: &PersistedRegistry,
) -> Result<usize, String> {
    let mut count = 0usize;

    macro_rules! put_many {
        ($kind:expr, $items:expr, $id:expr) => {
            for item in $items {
                let id = $id(&item);
                put_resource(metadata, None, $kind, &id, &item).await?;
                count += 1;
            }
        };
    }

    put_many!("snapshot", &persisted.snapshots, |s: &TreeSnapshot| s
        .id
        .as_str()
        .to_string());
    for reference in &persisted.refs {
        put_resource(
            metadata,
            Some(&reference.repository_id),
            "ref",
            &ref_id(&reference.repository_id, &reference.name),
            reference,
        )
        .await?;
        count += 1;
    }
    put_many!("workspace", &persisted.workspaces, |w: &AgentWorkspace| w
        .id
        .as_str()
        .to_string());
    put_many!("changeset", &persisted.changesets, |c: &ChangeSet| c
        .id
        .as_str()
        .to_string());
    put_many!("proposal", &persisted.proposals, |p: &Proposal| p
        .id
        .as_str()
        .to_string());
    put_many!("merge_intent", &persisted.merge_intents, |i: &MergeIntent| i
        .id
        .as_str()
        .to_string());
    put_many!("release_gate", &persisted.release_gates, |g: &ReleaseGate| g
        .id
        .as_str()
        .to_string());
    put_many!("environment", &persisted.environments, |e: &Environment| e
        .id
        .as_str()
        .to_string());
    put_many!(
        "environment_variable",
        &persisted.environment_variables,
        |v: &EnvironmentVariable| v.id.as_str().to_string()
    );
    put_many!(
        "environment_variable_version",
        &persisted.environment_variable_versions,
        |v: &EnvironmentVariableVersion| v.id.as_str().to_string()
    );
    put_many!(
        "environment_variable_change",
        &persisted.environment_variable_changes,
        |c: &EnvironmentVariableChange| c.id.as_str().to_string()
    );
    put_many!("integration", &persisted.integrations, |i: &IntegrationActor| i
        .provider
        .clone());
    put_many!("policy", &persisted.policies, |p: &VisibilityPolicy| p
        .id
        .as_str()
        .to_string());
    put_many!(
        "cedar_policy_document",
        &persisted.cedar_policy_documents,
        |d: &StoredCedarPolicyDocument| d.id.clone()
    );
    put_many!(
        "vector_manifest",
        &persisted.vector_manifests,
        |m: &VectorIndexManifest| m.id.as_str().to_string()
    );
    put_many!("projection", &persisted.projections, |p: &Projection| p
        .id
        .as_str()
        .to_string());
    put_many!("git_export", &persisted.git_exports, |g: &GitExport| g
        .id
        .as_str()
        .to_string());
    put_many!(
        "git_migration_record",
        &persisted.git_migration_records,
        |r: &GitMigrationRecord| r.id.as_str().to_string()
    );
    put_many!("operation", &persisted.operations, |o: &Operation| o
        .id
        .as_str()
        .to_string());
    put_many!("deploy_intent", &persisted.deploy_intents, |i: &DeployIntent| i
        .id
        .as_str()
        .to_string());
    put_many!(
        "deployment_grant",
        &persisted.deployment_grants,
        |g: &DeploymentGrant| g.id.as_str().to_string()
    );
    for config in &persisted.deploy_configs {
        let id = format!("{}:{}", config.repository_id.as_str(), config.service_id);
        put_resource(metadata, Some(&config.repository_id), "deploy_config", &id, config).await?;
        count += 1;
    }
    put_many!("auth_token", &persisted.auth_tokens, |t: &AuthToken| t
        .id
        .as_str()
        .to_string());
    put_many!(
        "proposal_comment",
        &persisted.proposal_comments,
        |c: &ProposalComment| c.id.as_str().to_string()
    );
    put_many!(
        "proposal_check",
        &persisted.proposal_checks,
        |c: &ProposalStatusCheck| c.id.as_str().to_string()
    );
    put_many!(
        "webhook_endpoint",
        &persisted.webhook_endpoints,
        |e: &WebhookEndpoint| e.id.as_str().to_string()
    );
    put_many!("webhook_event", &persisted.webhook_events, |e: &WebhookEvent| e
        .id
        .as_str()
        .to_string());
    put_many!("sync_session", &persisted.sync_sessions, |s: &SyncSession| s
        .id
        .as_str()
        .to_string());
    put_many!(
        "chunk_manifest",
        &persisted.chunk_manifests,
        |m: &ChunkTransferManifest| m.session_id.as_str().to_string()
    );
    for record in &persisted.sync_chunks {
        let id = format!("{}:{}", record.session_id.as_str(), record.chunk.id.as_str());
        put_resource(metadata, None, "sync_chunk", &id, record).await?;
        count += 1;
    }
    put_many!(
        "vector_index_job",
        &persisted.vector_index_jobs,
        |j: &VectorIndexJob| j.id.as_str().to_string()
    );

    Ok(count)
}

async fn put_resource<T: Serialize>(
    metadata: &PostgresMetadataStore,
    repository_id: Option<&RepositoryId>,
    kind: &str,
    id: &str,
    value: &T,
) -> Result<(), String> {
    let value = serde_json::to_value(value).map_err(|error| error.to_string())?;
    RegistryStore::put_resource(metadata, repository_id, kind, id, value)
        .await
        .map_err(|error| error.to_string())
}

async fn upload_bytes(
    blob_store: &ObjectBlobStore,
    hash: &ContentHash,
    bytes: &[u8],
    report: &mut ImportFileReport,
) -> Result<bool, String> {
    if BlobStore::exists(blob_store, hash)
        .await
        .map_err(|error| error.to_string())?
    {
        report.skipped_existing_object_store_blobs += 1;
        return Ok(false);
    }
    BlobStore::put(blob_store, hash, bytes)
        .await
        .map_err(|error| error.to_string())?;
    Ok(true)
}

async fn copy_source_blob_store(
    source_root: &Path,
    destination: &ObjectBlobStore,
    report: &mut ImportFileReport,
) -> Result<(usize, usize), String> {
    let mut files = Vec::new();
    collect_blob_files(source_root, &mut files);
    let seen = files.len();
    let mut copied = 0usize;
    for (hash, path) in files {
        if BlobStore::exists(destination, &hash)
            .await
            .map_err(|error| error.to_string())?
        {
            report.skipped_existing_object_store_blobs += 1;
            continue;
        }
        BlobStore::put_from_path(destination, &hash, &path)
            .await
            .map_err(|error| error.to_string())?;
        copied += 1;
    }
    Ok((seen, copied))
}

fn collect_blob_files(root: &Path, out: &mut Vec<(ContentHash, PathBuf)>) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_blob_files(&path, out);
            continue;
        }
        if let Some(hash) = hash_from_blob_path(root, &path) {
            out.push((hash, path));
        }
    }
}

fn count_blob_store_files(root: &Path) -> usize {
    let mut files = Vec::new();
    collect_blob_files(root, &mut files);
    files.len()
}

fn hash_from_blob_path(root: &Path, path: &Path) -> Option<ContentHash> {
    let relative = path.strip_prefix(root).ok()?;
    let parts: Vec<_> = relative.iter().filter_map(|part| part.to_str()).collect();
    // Expected: blobs/sha256/ab/cd/<digest> OR URL-encoded variants from older stores.
    let digest = parts.last()?.to_string();
    let digest = digest
        .rsplit('%')
        .next()
        .unwrap_or(&digest)
        .trim_matches(|ch| ch == '/' || ch == '\\')
        .to_string();
    if digest.len() != 64 || !digest.chars().all(|ch| ch.is_ascii_hexdigit()) {
        // Handle URL-encoded filenames like blobs%2Fsha256%2Faa%2Fbb%2Fdigest
        if let Some(decoded) = decode_url_encoded_blob_name(path.file_name()?.to_str()?) {
            return Some(decoded);
        }
        return None;
    }
    Some(ContentHash {
        algorithm: "sha256".to_string(),
        digest,
    })
}

fn decode_url_encoded_blob_name(name: &str) -> Option<ContentHash> {
    let decoded = name.replace("%2F", "/").replace("%2f", "/");
    let digest = decoded.rsplit('/').next()?.to_string();
    if digest.len() == 64 && digest.chars().all(|ch| ch.is_ascii_hexdigit()) {
        Some(ContentHash {
            algorithm: "sha256".to_string(),
            digest,
        })
    } else {
        None
    }
}

fn content_hash_from_digest(raw: &str) -> Option<ContentHash> {
    let digest = raw.strip_prefix("sha256:")?;
    Some(ContentHash {
        algorithm: "sha256".to_string(),
        digest: digest.to_string(),
    })
}

fn count_other_resources(persisted: &PersistedRegistry) -> usize {
    persisted.snapshots.len()
        + persisted.refs.len()
        + persisted.workspaces.len()
        + persisted.changesets.len()
        + persisted.proposals.len()
        + persisted.merge_intents.len()
        + persisted.release_gates.len()
        + persisted.environments.len()
        + persisted.environment_variables.len()
        + persisted.environment_variable_versions.len()
        + persisted.environment_variable_changes.len()
        + persisted.integrations.len()
        + persisted.policies.len()
        + persisted.cedar_policy_documents.len()
        + persisted.vector_manifests.len()
        + persisted.projections.len()
        + persisted.git_exports.len()
        + persisted.git_migration_records.len()
        + persisted.operations.len()
        + persisted.deploy_intents.len()
        + persisted.deployment_grants.len()
        + persisted.deploy_configs.len()
        + persisted.auth_tokens.len()
        + persisted.proposal_comments.len()
        + persisted.proposal_checks.len()
        + persisted.webhook_endpoints.len()
        + persisted.webhook_events.len()
        + persisted.sync_sessions.len()
        + persisted.chunk_manifests.len()
        + persisted.sync_chunks.len()
        + persisted.vector_index_jobs.len()
        + persisted.oci_upload_sessions.len()
        + persisted.oci_provenance.len()
}
