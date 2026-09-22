use anyhow::{Context, Result};
use bytes::Bytes;
use futures::{StreamExt, TryStreamExt, stream};
use nebula_core::{
    Actor, BlobChunk, BlobChunkId, ChunkTransferManifest, CodeEmbeddingChunk, ContentBlob,
    ContentHash, Ref, RepositoryId, SyncSession, SyncSessionId, TreeSnapshotId, VectorIndexJob,
    VectorIndexManifest, VectorIndexManifestId,
};
use nebula_local::{LocalRepo, LocalSyncBundle};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use tokio::io::AsyncWriteExt;
use tokio_util::io::ReaderStream;

const DEFAULT_UPLOAD_CONCURRENCY: usize = 32;
const MAX_UPLOAD_CONCURRENCY: usize = 128;
const MISSING_BLOB_PREFLIGHT_BATCH_SIZE: usize = 25;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum SyncDirection {
    Push,
    Pull,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StartSyncSessionRequest {
    pub direction: SyncDirection,
    pub base_ref: Option<String>,
    pub lease_token: String,
    pub actor: Actor,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SyncResumeState {
    pub repository_id: RepositoryId,
    pub session_id: SyncSessionId,
    pub uploaded_chunks: Vec<BlobChunkId>,
    pub downloaded_chunks: Vec<BlobChunkId>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SyncChunkUploadRequest {
    pub chunk: BlobChunk,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SyncChunkRecord {
    pub repository_id: RepositoryId,
    pub session_id: SyncSessionId,
    pub chunk: BlobChunk,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SyncSessionValidation {
    pub session_id: SyncSessionId,
    pub valid: bool,
    pub missing_chunks: Vec<BlobChunkId>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BlobPresenceRequest {
    pub blobs: Vec<ContentBlob>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BlobPresenceResponse {
    pub present: Vec<ContentHash>,
    pub missing: Vec<ContentBlob>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BlobUploadBatchRequest {
    pub blobs: Vec<ContentBlob>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BlobUploadBatchResponse {
    pub present: Vec<ContentHash>,
    pub uploads: Vec<BlobUploadAction>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BlobUploadAction {
    pub blob: ContentBlob,
    pub transfer: BlobUploadTransfer,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BlobUploadTransfer {
    DirectPut {
        url: String,
        headers: std::collections::BTreeMap<String, String>,
        expires_at_unix_ms: u64,
    },
    RegistryPut,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BlobUploadConfirmRequest {
    pub blobs: Vec<ContentBlob>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BlobUploadConfirmResponse {
    pub uploaded: Vec<ContentHash>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ResolveRefResponse {
    pub reference: Ref,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BlobPackEntry {
    pub blob: ContentBlob,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BlobPackUploadRequest {
    pub blobs: Vec<BlobPackEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BlobPackUploadResponse {
    pub uploaded: Vec<ContentHash>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VectorIndexRequest {
    pub snapshot_id: Option<TreeSnapshotId>,
    pub projection_id: Option<nebula_core::ProjectionId>,
    pub actor: Actor,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VectorIndexResponse {
    pub manifest: VectorIndexManifest,
    pub job: VectorIndexJob,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VectorSearchRequest {
    pub manifest_id: Option<VectorIndexManifestId>,
    pub snapshot_id: Option<TreeSnapshotId>,
    pub query: String,
    pub top_k: Option<usize>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VectorSearchHit {
    pub path: String,
    pub start_line: Option<u32>,
    pub end_line: Option<u32>,
    pub score: f32,
    pub snippet: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VectorSearchResponse {
    pub manifest_id: VectorIndexManifestId,
    pub hits: Vec<VectorSearchHit>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VectorExplainRequest {
    pub manifest_id: VectorIndexManifestId,
    pub path: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VectorExplainResponse {
    pub manifest_id: VectorIndexManifestId,
    pub path: String,
    pub chunk: Option<CodeEmbeddingChunk>,
}

#[derive(Clone, Debug)]
pub struct RegistrySyncClient {
    base_url: String,
    bearer_token: Option<String>,
    client: reqwest::Client,
}

impl RegistrySyncClient {
    pub fn new(base_url: impl Into<String>, bearer_token: Option<String>) -> Self {
        let base_url = base_url.into().trim_end_matches('/').to_string();
        let client = Self::build_sync_client();
        Self {
            base_url,
            bearer_token,
            client,
        }
    }

    fn build_sync_client() -> reqwest::Client {
        let connect_timeout_secs = Self::numeric_env("NEBULA_SYNC_CONNECT_TIMEOUT", 30);
        let pool_idle_timeout_secs = Self::numeric_env("NEBULA_SYNC_POOL_IDLE_TIMEOUT", 60);
        let tcp_keepalive_secs = Self::numeric_env("NEBULA_SYNC_TCP_KEEPALIVE", 30);
        let pool_max_idle_per_host = Self::numeric_env("NEBULA_SYNC_POOL_MAX_IDLE_PER_HOST", 16) as usize;
        let mut builder = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(connect_timeout_secs))
            .pool_idle_timeout(std::time::Duration::from_secs(pool_idle_timeout_secs))
            .tcp_keepalive(std::time::Duration::from_secs(tcp_keepalive_secs))
            .pool_max_idle_per_host(Self::numeric_env("NEBULA_SYNC_POOL_MAX_IDLE_PER_HOST", 16) as usize);
        if let Ok(user_agent) = std::env::var("NEBULA_USER_AGENT") {
            if !user_agent.is_empty() {
                builder = builder.user_agent(user_agent);
            }
        }
        builder.build().expect("invalid reqwest client configuration")
    }

    const DEFAULT_PUSH_MAX_RETRIES: u32 = 5;
    const DEFAULT_RETRY_BASE_DELAY_MS: u64 = 250;
    const MAXIMUM_RETRY_DELAY_MS: u64 = 15_000;
    const RETRY_JITTER_MS: u64 = 250;

    fn numeric_env(name: &str, default: u64) -> u64 {
        std::env::var(name)
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(default)
    }

    fn push_max_retries() -> u32 {
        std::env::var("NEBULA_PUSH_MAX_RETRIES")
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(Self::DEFAULT_PUSH_MAX_RETRIES)
    }

    fn is_transient_error(error: &anyhow::Error) -> bool {
        let mut source: Option<&(dyn std::error::Error + 'static)> = Some(error.as_ref());
        while let Some(err) = source {
            if let Some(reqwest_error) = err.downcast_ref::<reqwest::Error>() {
                if reqwest_error.is_connect() || reqwest_error.is_timeout() || reqwest_error.is_body() {
                    return true;
                }
            }
            source = err.source();
        }
        let text = format!("{error:?}").to_ascii_lowercase();
        text.contains("connection reset")
            || text.contains("broken pipe")
            || text.contains("connect error")
            || text.contains("timed out")
            || text.contains("operation timed out")
            || text.contains("connection refused")
            || text.contains("connection closed")
            || text.contains("eof")
            || text.contains("empty reply")
            || text.contains("registry request failed with 408")
            || text.contains("registry request failed with 429")
            || text.contains("registry request failed with 502")
            || text.contains("registry request failed with 503")
            || text.contains("registry request failed with 504")
            || text.contains("registry request failed with 524")
    }

    async fn retry_transient<T, F, Fut>(mut make_attempt: F) -> Result<T>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        let max_retries = Self::push_max_retries();
        let base_delay_ms = Self::numeric_env("NEBULA_PUSH_RETRY_BACKOFF_MS", Self::DEFAULT_RETRY_BASE_DELAY_MS);
        let mut attempt: u32 = 0;
        let mut last_error: Option<anyhow::Error> = None;
        loop {
            match make_attempt().await {
                Ok(value) => return Ok(value),
                Err(error) => {
                    last_error = Some(error);
                    if attempt >= max_retries {
                        break;
                    }
                    if !Self::is_transient_error(last_error.as_ref().unwrap()) {
                        break;
                    }
                    attempt += 1;
                    let mut delay_ms = base_delay_ms.saturating_mul((1u64 << attempt).saturating_sub(1));
                    if delay_ms > Self::MAXIMUM_RETRY_DELAY_MS {
                        delay_ms = Self::MAXIMUM_RETRY_DELAY_MS;
                    }
                    let jitter_nanos = (std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.subsec_nanos() % (Self::RETRY_JITTER_MS as u32 * 1_000_000))
                        .unwrap_or(0)) as u64;
                    tokio::time::sleep(std::time::Duration::from_millis(delay_ms) + std::time::Duration::from_nanos(jitter_nanos)).await;
                }
            }
        }
        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("retry exhausted without an error")))
    }

    pub async fn push_repo(
        &self,
        repo: &LocalRepo,
        repository_id_override: Option<RepositoryId>,
    ) -> Result<LocalSyncBundle> {
        let mut bundle = repo.export_bundle_metadata()?;
        if let Some(id) = repository_id_override {
            bundle.repository_id = id.clone();
            for reference in &mut bundle.refs {
                reference.repository_id = id.clone();
            }
            for snapshot in &mut bundle.snapshots {
                snapshot.repository_id = id.clone();
            }
            for changeset in &mut bundle.changesets {
                changeset.repository_id = id.clone();
            }
            for proposal in &mut bundle.proposals {
                proposal.repository_id = id.clone();
            }
            for operation in &mut bundle.operations {
                operation.repository_id = id.clone();
            }
            for record in &mut bundle.git_migration_records {
                record.repository_id = id.clone();
            }
            for variable in &mut bundle.environment_variables {
                variable.repository_id = id.clone();
            }
            for version in &mut bundle.environment_variable_versions {
                version.repository_id = id.clone();
            }
        }
        let refs = bundle.refs.clone();
        let mut bundle_without_refs = bundle.clone();
        bundle_without_refs.refs = Vec::new();
        let debug_timing = std::env::var("NEBULA_DEBUG_PUSH_TIMING").is_ok();
        macro_rules! timed {
            ($label:expr, $body:expr) => {{
                let started = std::time::Instant::now();
                let result = $body;
                if debug_timing {
                    eprintln!("[push-timing] {} took {:?}", $label, started.elapsed());
                }
                result
            }};
        }
        let session = Self::retry_transient(|| async {
            self.start_session(
                &bundle.repository_id,
                &StartSyncSessionRequest {
                    direction: SyncDirection::Push,
                    base_ref: Some(bundle.default_ref.clone()),
                    lease_token: format!("lease-{}", bundle.repository_id),
                    actor: Actor::Public,
                },
            )
            .await
        })
        .await?;
        let chunk_descriptors = bundle
            .blobs
            .iter()
            .flat_map(|record| {
                vec![nebula_core::BlobChunkDescriptor {
                    blob_hash: Some(record.blob.hash.clone()),
                    hash: record.blob.hash.clone(),
                    offset: 0,
                    size_bytes: record.blob.size_bytes,
                    digest: record.blob.hash.digest.clone(),
                }]
            })
            .collect::<Vec<_>>();
        let manifest = ChunkTransferManifest {
            repository_id: bundle.repository_id.clone(),
            session_id: session.id.clone(),
            total_bytes: chunk_descriptors.iter().map(|chunk| chunk.size_bytes).sum(),
            chunks: chunk_descriptors,
        };
        timed!(
            "put_chunk_manifest",
            Self::retry_transient(|| async {
                self.put_chunk_manifest(&bundle.repository_id, &session.id, &manifest)
                    .await
            })
            .await
        )?;
        let blobs = bundle
            .blobs
            .iter()
            .map(|record| record.blob.clone())
            .collect::<Vec<_>>();
        if let Some(plan) = timed!(
            "plan_blob_uploads",
            Self::retry_transient(|| async {
                self.plan_blob_uploads(&bundle.repository_id, &session.id, blobs.clone())
                    .await
            })
            .await
        )? {
            let uploads = plan.uploads;
            timed!(
                "upload_planned_blobs",
                Self::retry_transient(|| async {
                    self.upload_planned_blobs(&bundle.repository_id, &session.id, repo, uploads.clone())
                        .await
                })
                .await
            )?;
        } else {
            timed!(
                "upload_legacy_missing_blobs",
                Self::retry_transient(|| async {
                    self.upload_legacy_missing_blobs(&bundle.repository_id, &session.id, repo, &bundle)
                        .await
                })
                .await
            )?;
        }
        timed!(
            "put_session_bundle",
            Self::retry_transient(|| async {
                self.put_session_bundle(&bundle.repository_id, &session.id, &bundle_without_refs)
                    .await
            })
            .await
        )?;
        let validation = timed!(
            "validate_session",
            Self::retry_transient(|| async {
                self.validate_session(&bundle.repository_id, &session.id)
                    .await
            })
            .await
        )?;
        if !validation.valid {
            anyhow::bail!(
                "sync validation failed; missing {} chunk(s)",
                validation.missing_chunks.len()
            );
        }
        timed!(
            "commit_session",
            Self::retry_transient(|| async {
                self.commit_session(&bundle.repository_id, &session.id)
                    .await
            })
            .await
        )?;
        for reference in &refs {
            timed!(
                "upsert_ref",
                Self::retry_transient(|| async {
                    self.upsert_ref(&bundle.repository_id, reference).await
                })
                .await
            )?;
        }
        Ok(bundle)
    }

    async fn upsert_ref(&self, repository_id: &RepositoryId, reference: &Ref) -> Result<()> {
        let url = format!("{}/v1/galaxies/{}/refs", self.base_url, repository_id);
        let expected = self.get_ref(repository_id, &reference.name).await?;
        let mut request = self.authorize(self.client.put(&url).json(reference));
        if let Some(current) = &expected {
            let target_json = serde_json::to_string(&current.target)
                .context("failed to encode current ref target for CAS")?;
            request = request.header("if-nebula-ref-target", target_json);
        }
        let response = request.send().await?;
        if response.status() == reqwest::StatusCode::CONFLICT {
            let current = self
                .get_ref(repository_id, &reference.name)
                .await?
                .ok_or_else(|| {
                    anyhow::anyhow!("ref {} disappeared during CAS retry", reference.name)
                })?;
            let target_json = serde_json::to_string(&current.target)
                .context("failed to encode current ref target for CAS retry")?;
            Self::error_for_status(
                self.authorize(self.client.put(&url).json(reference))
                    .header("if-nebula-ref-target", target_json)
                    .send()
                    .await?,
            )
            .await?;
        } else {
            Self::error_for_status(response).await?;
        }
        Ok(())
    }

    async fn get_ref(&self, repository_id: &RepositoryId, name: &str) -> Result<Option<Ref>> {
        let url = format!(
            "{}/v1/galaxies/{}/refs/{}",
            self.base_url, repository_id, name
        );
        let response = self.authorize(self.client.get(url)).send().await?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        Self::error_for_status(response)
            .await?
            .json::<ResolveRefResponse>()
            .await
            .map(|response| Some(response.reference))
            .context("failed to decode registry ref")
    }

    pub async fn pull_repo(&self, repo: &LocalRepo) -> Result<LocalSyncBundle> {
        let config = repo.config()?;
        let bundle = self.get_bundle(&config.repository_id).await?;
        for record in &bundle.blobs {
            if record.bytes.is_empty() {
                self.download_blob(&config.repository_id, repo, &record.blob)
                    .await?;
            }
        }
        repo.import_bundle(&bundle)?;
        Ok(bundle)
    }

    pub async fn get_bundle(&self, repository_id: &RepositoryId) -> Result<LocalSyncBundle> {
        let url = format!(
            "{}/v1/galaxies/{}/sync-bundle",
            self.base_url, repository_id
        );
        let request = self.authorize(self.client.get(url));
        Self::error_for_status(request.send().await?)
            .await?
            .json::<LocalSyncBundle>()
            .await
            .context("failed to decode registry sync bundle")
    }

    pub async fn put_bundle(
        &self,
        repository_id: &RepositoryId,
        bundle: &LocalSyncBundle,
    ) -> Result<()> {
        let url = format!(
            "{}/v1/galaxies/{}/sync-bundle",
            self.base_url, repository_id
        );
        let request = self.authorize(self.client.put(url).json(bundle));
        Self::error_for_status(request.send().await?).await?;
        Ok(())
    }

    pub async fn start_session(
        &self,
        repository_id: &RepositoryId,
        request: &StartSyncSessionRequest,
    ) -> Result<SyncSession> {
        let url = format!(
            "{}/v1/galaxies/{}/sync-sessions",
            self.base_url, repository_id
        );
        Self::error_for_status(
            self.authorize(self.client.post(url).json(request))
                .send()
                .await?,
        )
        .await?
        .json::<SyncSession>()
        .await
        .context("failed to decode sync session")
    }

    pub async fn put_chunk_manifest(
        &self,
        repository_id: &RepositoryId,
        session_id: &SyncSessionId,
        manifest: &ChunkTransferManifest,
    ) -> Result<ChunkTransferManifest> {
        let url = format!(
            "{}/v1/galaxies/{}/sync-sessions/{}/chunks",
            self.base_url, repository_id, session_id
        );
        Self::error_for_status(
            self.authorize(self.client.put(url).json(manifest))
                .send()
                .await?,
        )
        .await?
        .json::<ChunkTransferManifest>()
        .await
        .context("failed to decode chunk transfer manifest")
    }

    pub async fn upload_chunk(
        &self,
        repository_id: &RepositoryId,
        session_id: &SyncSessionId,
        chunk: &BlobChunk,
        bytes: &[u8],
    ) -> Result<SyncChunkRecord> {
        let url = format!(
            "{}/v1/galaxies/{}/sync-sessions/{}/chunks/{}",
            self.base_url, repository_id, session_id, chunk.id
        );
        let request = SyncChunkUploadRequest {
            chunk: chunk.clone(),
            bytes: bytes.to_vec(),
        };
        Self::error_for_status(
            self.authorize(self.client.put(url).json(&request))
                .send()
                .await?,
        )
        .await?
        .json::<SyncChunkRecord>()
        .await
        .context("failed to decode uploaded sync chunk")
    }

    pub async fn upload_blob(
        &self,
        repository_id: &RepositoryId,
        session_id: &SyncSessionId,
        repo: &LocalRepo,
        hash: &nebula_core::ContentHash,
    ) -> Result<()> {
        let url = format!(
            "{}/v1/galaxies/{}/sync-sessions/{}/blobs/{}/{}",
            self.base_url, repository_id, session_id, hash.algorithm, hash.digest
        );
        let file = tokio::fs::File::open(repo.blob_path(hash))
            .await
            .with_context(|| format!("failed to open local blob {}", hash.digest))?;
        let stream = ReaderStream::new(file).map_ok(Bytes::from);
        let response = self
            .authorize(
                self.client
                    .put(url)
                    .body(reqwest::Body::wrap_stream(stream)),
            )
            .send()
            .await?;
        Self::error_for_status(response).await?;
        Ok(())
    }

    pub async fn plan_blob_uploads(
        &self,
        repository_id: &RepositoryId,
        session_id: &SyncSessionId,
        blobs: Vec<ContentBlob>,
    ) -> Result<Option<BlobUploadBatchResponse>> {
        let url = format!(
            "{}/v1/galaxies/{}/sync-sessions/{}/blob-uploads/batch",
            self.base_url, repository_id, session_id
        );
        let response = self
            .authorize(
                self.client
                    .post(url)
                    .json(&BlobUploadBatchRequest { blobs }),
            )
            .send()
            .await?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let response = Self::error_for_status(response).await?;
        response
            .json::<BlobUploadBatchResponse>()
            .await
            .map(Some)
            .context("failed to decode blob upload plan")
    }

    async fn upload_planned_blobs(
        &self,
        repository_id: &RepositoryId,
        session_id: &SyncSessionId,
        repo: &LocalRepo,
        uploads: Vec<BlobUploadAction>,
    ) -> Result<()> {
        let concurrency = upload_concurrency();
        let upload_repository_id = repository_id.clone();
        let upload_session_id = session_id.clone();
        let mut direct_blobs = Vec::new();
        let mut upload_stream = stream::iter(uploads.into_iter().map(|action| {
            let repository_id = upload_repository_id.clone();
            let session_id = upload_session_id.clone();
            async move {
                self.upload_planned_blob(&repository_id, &session_id, repo, action)
                    .await
            }
        }))
        .buffer_unordered(concurrency);
        while let Some(result) = upload_stream.next().await {
            if let Some(blob) = result? {
                direct_blobs.push(blob);
            }
        }
        if !direct_blobs.is_empty() {
            self.confirm_blob_uploads(repository_id, session_id, direct_blobs)
                .await?;
        }
        Ok(())
    }

    async fn upload_planned_blob(
        &self,
        repository_id: &RepositoryId,
        session_id: &SyncSessionId,
        repo: &LocalRepo,
        action: BlobUploadAction,
    ) -> Result<Option<ContentBlob>> {
        match action.transfer {
            BlobUploadTransfer::DirectPut { url, headers, .. } if direct_uploads_enabled() => {
                self.upload_blob_direct(repo, &action.blob, &url, headers)
                    .await
                    .with_context(|| {
                        format!("failed direct upload for blob {}", action.blob.hash.digest)
                    })?;
                Ok(Some(action.blob))
            }
            BlobUploadTransfer::DirectPut { .. } | BlobUploadTransfer::RegistryPut => {
                self.upload_blob(repository_id, session_id, repo, &action.blob.hash)
                    .await
                    .with_context(|| {
                        format!(
                            "failed registry upload for blob {}",
                            action.blob.hash.digest
                        )
                    })?;
                Ok(None)
            }
        }
    }

    async fn upload_blob_direct(
        &self,
        repo: &LocalRepo,
        blob: &ContentBlob,
        url: &str,
        headers: std::collections::BTreeMap<String, String>,
    ) -> Result<()> {
        let path = repo.blob_path(&blob.hash);
        let file = tokio::fs::File::open(&path)
            .await
            .with_context(|| format!("failed to open local blob {}", blob.hash.digest))?;
        let metadata = file
            .metadata()
            .await
            .with_context(|| format!("failed to stat local blob {}", blob.hash.digest))?;
        if metadata.len() != blob.size_bytes {
            anyhow::bail!(
                "local blob {} has size {}, expected {}",
                blob.hash.digest,
                metadata.len(),
                blob.size_bytes
            );
        }
        let stream = ReaderStream::new(file).map_ok(Bytes::from);
        let mut request = self
            .client
            .put(url)
            .header(reqwest::header::CONTENT_LENGTH, blob.size_bytes.to_string())
            .body(reqwest::Body::wrap_stream(stream));
        for (name, value) in headers {
            let name = reqwest::header::HeaderName::from_bytes(name.as_bytes())
                .with_context(|| format!("invalid direct upload header name {name}"))?;
            let value = reqwest::header::HeaderValue::from_str(&value)
                .with_context(|| format!("invalid direct upload header value for {name}"))?;
            request = request.header(name, value);
        }
        Self::error_for_status(request.send().await?).await?;
        Ok(())
    }

    pub async fn confirm_blob_uploads(
        &self,
        repository_id: &RepositoryId,
        session_id: &SyncSessionId,
        blobs: Vec<ContentBlob>,
    ) -> Result<BlobUploadConfirmResponse> {
        let url = format!(
            "{}/v1/galaxies/{}/sync-sessions/{}/blob-uploads/confirm",
            self.base_url, repository_id, session_id
        );
        Self::error_for_status(
            self.authorize(
                self.client
                    .post(url)
                    .json(&BlobUploadConfirmRequest { blobs }),
            )
            .send()
            .await?,
        )
        .await?
        .json::<BlobUploadConfirmResponse>()
        .await
        .context("failed to decode direct upload confirmation")
    }

    async fn upload_legacy_missing_blobs(
        &self,
        repository_id: &RepositoryId,
        session_id: &SyncSessionId,
        repo: &LocalRepo,
        bundle: &LocalSyncBundle,
    ) -> Result<()> {
        let missing = self
            .missing_blobs_batched(
                repository_id,
                session_id,
                bundle
                    .blobs
                    .iter()
                    .map(|record| record.blob.clone())
                    .collect(),
            )
            .await?;
        let missing_hashes = missing
            .missing
            .iter()
            .map(|blob| blob.hash.clone())
            .collect::<BTreeSet<_>>();
        let missing_records = bundle
            .blobs
            .iter()
            .filter(|record| missing_hashes.contains(&record.blob.hash))
            .cloned()
            .collect::<Vec<_>>();
        let concurrency = upload_concurrency();
        let mut uploads = stream::iter(missing_records.into_iter().map(|record| {
            let hash = record.blob.hash.clone();
            async move {
                self.upload_blob(repository_id, session_id, repo, &hash)
                    .await
                    .with_context(|| format!("failed to upload blob {}", hash.digest))
            }
        }))
        .buffer_unordered(concurrency);
        while let Some(result) = uploads.next().await {
            result?;
        }
        Ok(())
    }

    pub async fn missing_blobs(
        &self,
        repository_id: &RepositoryId,
        session_id: &SyncSessionId,
        blobs: Vec<ContentBlob>,
    ) -> Result<BlobPresenceResponse> {
        let url = format!(
            "{}/v1/galaxies/{}/sync-sessions/{}/missing-blobs",
            self.base_url, repository_id, session_id
        );
        Self::error_for_status(
            self.authorize(self.client.post(url).json(&BlobPresenceRequest { blobs }))
                .send()
                .await?,
        )
        .await?
        .json::<BlobPresenceResponse>()
        .await
        .context("failed to decode missing blob response")
    }

    pub async fn missing_blobs_batched(
        &self,
        repository_id: &RepositoryId,
        session_id: &SyncSessionId,
        blobs: Vec<ContentBlob>,
    ) -> Result<BlobPresenceResponse> {
        let mut present = Vec::new();
        let mut missing = Vec::new();
        for batch in blobs.chunks(MISSING_BLOB_PREFLIGHT_BATCH_SIZE) {
            let response = self
                .missing_blobs(repository_id, session_id, batch.to_vec())
                .await?;
            present.extend(response.present);
            missing.extend(response.missing);
        }
        Ok(BlobPresenceResponse { present, missing })
    }

    pub async fn upload_blob_pack(
        &self,
        repository_id: &RepositoryId,
        session_id: &SyncSessionId,
        blobs: Vec<BlobPackEntry>,
    ) -> Result<BlobPackUploadResponse> {
        let url = format!(
            "{}/v1/galaxies/{}/sync-sessions/{}/blob-pack",
            self.base_url, repository_id, session_id
        );
        Self::error_for_status(
            self.authorize(self.client.put(url).json(&BlobPackUploadRequest { blobs }))
                .send()
                .await?,
        )
        .await?
        .json::<BlobPackUploadResponse>()
        .await
        .context("failed to decode blob pack upload response")
    }

    pub async fn download_blob(
        &self,
        repository_id: &RepositoryId,
        repo: &LocalRepo,
        blob: &nebula_core::ContentBlob,
    ) -> Result<()> {
        let url = format!(
            "{}/v1/galaxies/{}/sync-sessions/pull/blobs/{}/{}",
            self.base_url, repository_id, blob.hash.algorithm, blob.hash.digest
        );
        let tmp_path = std::env::temp_dir().join(format!(
            "nebula-pull-{}-{}",
            blob.hash.algorithm, blob.hash.digest
        ));
        let response =
            Self::error_for_status(self.authorize(self.client.get(url)).send().await?).await?;
        let mut file = tokio::fs::File::create(&tmp_path).await?;
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            file.write_all(&chunk).await?;
        }
        file.sync_all().await?;
        drop(file);
        repo.write_blob_from_path(blob, &tmp_path)?;
        let _ = tokio::fs::remove_file(tmp_path).await;
        Ok(())
    }

    pub async fn put_session_bundle(
        &self,
        repository_id: &RepositoryId,
        session_id: &SyncSessionId,
        bundle: &LocalSyncBundle,
    ) -> Result<()> {
        let url = format!(
            "{}/v1/galaxies/{}/sync-sessions/{}/bundle",
            self.base_url, repository_id, session_id
        );
        Self::error_for_status(
            self.authorize(self.client.put(url).json(bundle))
                .send()
                .await?,
        )
        .await?;
        Ok(())
    }

    pub async fn get_chunk(
        &self,
        repository_id: &RepositoryId,
        session_id: &SyncSessionId,
        chunk_id: &BlobChunkId,
    ) -> Result<SyncChunkRecord> {
        let url = format!(
            "{}/v1/galaxies/{}/sync-sessions/{}/chunks/{}",
            self.base_url, repository_id, session_id, chunk_id
        );
        Self::error_for_status(self.authorize(self.client.get(url)).send().await?)
            .await?
            .json::<SyncChunkRecord>()
            .await
            .context("failed to decode sync chunk")
    }

    pub async fn validate_session(
        &self,
        repository_id: &RepositoryId,
        session_id: &SyncSessionId,
    ) -> Result<SyncSessionValidation> {
        self.post_session_action(repository_id, session_id, "validate")
            .await?
            .json::<SyncSessionValidation>()
            .await
            .context("failed to decode sync validation")
    }

    pub async fn commit_session(
        &self,
        repository_id: &RepositoryId,
        session_id: &SyncSessionId,
    ) -> Result<SyncSession> {
        self.post_session_action(repository_id, session_id, "commit")
            .await?
            .json::<SyncSession>()
            .await
            .context("failed to decode committed sync session")
    }

    pub async fn abort_session(
        &self,
        repository_id: &RepositoryId,
        session_id: &SyncSessionId,
    ) -> Result<SyncSession> {
        self.post_session_action(repository_id, session_id, "abort")
            .await?
            .json::<SyncSession>()
            .await
            .context("failed to decode aborted sync session")
    }

    pub async fn create_vector_index(
        &self,
        repository_id: &RepositoryId,
        request: &VectorIndexRequest,
    ) -> Result<VectorIndexResponse> {
        let url = format!(
            "{}/v1/galaxies/{}/vector-indexes",
            self.base_url, repository_id
        );
        Self::error_for_status(
            self.authorize(self.client.post(url).json(request))
                .send()
                .await?,
        )
        .await?
        .json::<VectorIndexResponse>()
        .await
        .context("failed to decode vector index response")
    }

    pub async fn search_vector_index(
        &self,
        repository_id: &RepositoryId,
        request: &VectorSearchRequest,
    ) -> Result<VectorSearchResponse> {
        let url = format!(
            "{}/v1/galaxies/{}/vector-search",
            self.base_url, repository_id
        );
        Self::error_for_status(
            self.authorize(self.client.post(url).json(request))
                .send()
                .await?,
        )
        .await?
        .json::<VectorSearchResponse>()
        .await
        .context("failed to decode vector search response")
    }

    pub async fn explain_vector_chunk(
        &self,
        repository_id: &RepositoryId,
        request: &VectorExplainRequest,
    ) -> Result<VectorExplainResponse> {
        let url = format!(
            "{}/v1/galaxies/{}/vector-explain",
            self.base_url, repository_id
        );
        Self::error_for_status(
            self.authorize(self.client.post(url).json(request))
                .send()
                .await?,
        )
        .await?
        .json::<VectorExplainResponse>()
        .await
        .context("failed to decode vector explanation response")
    }

    async fn post_session_action(
        &self,
        repository_id: &RepositoryId,
        session_id: &SyncSessionId,
        action: &str,
    ) -> Result<reqwest::Response> {
        let url = format!(
            "{}/v1/galaxies/{}/sync-sessions/{}/{}",
            self.base_url, repository_id, session_id, action
        );
        Self::error_for_status(self.authorize(self.client.post(url)).send().await?).await
    }

    fn authorize(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.bearer_token {
            Some(token) => request.bearer_auth(token),
            None => request,
        }
    }

    async fn error_for_status(response: reqwest::Response) -> Result<reqwest::Response> {
        let status = response.status();
        if status.is_success() {
            return Ok(response);
        }
        let body = response.text().await.unwrap_or_default();
        let message = serde_json::from_str::<RegistryErrorBody>(&body)
            .ok()
            .and_then(|body| body.error.or(body.message).or(body.code))
            .filter(|message| !message.is_empty())
            .unwrap_or_else(|| body.trim().to_string());
        let guidance = match status.as_u16() {
            401 => "run `neb auth status` or `neb auth login` for this registry",
            403 => "check the active organization, repository binding, and API-key scopes",
            _ => "inspect the registry response and server logs",
        };
        anyhow::bail!(
            "registry request failed with {status}: {} ({guidance})",
            if message.is_empty() {
                "no error body".to_string()
            } else {
                message
            }
        )
    }
}

fn upload_concurrency() -> usize {
    std::env::var("NEBULA_UPLOAD_CONCURRENCY")
        .or_else(|_| std::env::var("NEBULA_SYNC_UPLOAD_CONCURRENCY"))
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_UPLOAD_CONCURRENCY)
        .min(MAX_UPLOAD_CONCURRENCY)
}

fn direct_uploads_enabled() -> bool {
    std::env::var("NEBULA_DIRECT_UPLOADS")
        .map(|value| {
            let value = value.trim().to_ascii_lowercase();
            value != "0" && value != "false" && value != "off"
        })
        .unwrap_or(true)
}

#[derive(Debug, Deserialize)]
struct RegistryErrorBody {
    error: Option<String>,
    message: Option<String>,
    code: Option<String>,
}

pub fn is_registry_remote(url: &str) -> bool {
    url.starts_with("http://") || url.starts_with("https://")
}

#[cfg(test)]
mod tests {
    #[test]
    fn production_blob_sync_does_not_collect_whole_bodies() {
        let source = include_str!("lib.rs");
        let file_read = ["fs", "::read(repo.blob_path"].concat();
        let response_collect = [".bytes()", "\n            .await"].concat();
        assert!(!source.contains(&file_read));
        assert!(!source.contains(&response_collect));
        assert!(source.contains("Body::wrap_stream"));
        assert!(source.contains("bytes_stream()"));
    }
}
