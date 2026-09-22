use async_trait::async_trait;
use nebula_core::{
    Actor, CodeEmbeddingChunk, ContentHash, NebulaResult, PolicyAction, PolicyDecision,
    PolicyEngine, PolicyObject, PolicyRequest, ProjectionId, RepositoryId, TreeSnapshotId,
    VectorIndexManifest, VectorIndexManifestId, VectorIndexStore, VisibilityPolicy,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    sync::{Arc, RwLock},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VectorIndexConfig {
    pub provider: String,
    pub connection_name: String,
    pub embedding_model: String,
    pub index_version: String,
}

impl Default for VectorIndexConfig {
    fn default() -> Self {
        Self {
            provider: "experimental-in-memory".to_string(),
            connection_name: "astracollab-compatible".to_string(),
            embedding_model: "experimental-path-content-hash-v1".to_string(),
            index_version: "nebula-code-index-experimental-v1".to_string(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SemanticSearchHit {
    pub path: String,
    pub start_line: Option<u32>,
    pub end_line: Option<u32>,
    pub score: f32,
    pub snippet: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExactTextSearchHit {
    pub path: String,
    pub line: Option<u32>,
    pub snippet: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum SymbolKind {
    Function,
    Class,
    Type,
    Import,
    Export,
    Route,
    Package,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SymbolSearchHit {
    pub path: String,
    pub symbol: String,
    pub kind: SymbolKind,
    pub line: Option<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ImportGraphEdge {
    pub from_path: String,
    pub imported: String,
    pub line: Option<u32>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct HybridSearchResults {
    pub exact: Vec<ExactTextSearchHit>,
    pub symbols: Vec<SymbolSearchHit>,
    pub semantic: Vec<SemanticSearchHit>,
    pub imports: Vec<ImportGraphEdge>,
}

#[derive(Clone, Debug)]
pub struct RetrievalPolicyContext {
    pub repository_id: RepositoryId,
    pub actor: Actor,
    pub policies: Vec<VisibilityPolicy>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TextIndexManifest {
    pub repository_id: RepositoryId,
    pub snapshot_id: TreeSnapshotId,
    pub projection_id: Option<ProjectionId>,
    pub shard_key: String,
    pub index_version: String,
    pub indexed_paths: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SymbolIndexManifest {
    pub repository_id: RepositoryId,
    pub snapshot_id: TreeSnapshotId,
    pub projection_id: Option<ProjectionId>,
    pub shard_key: String,
    pub index_version: String,
    pub symbol_count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HybridIndexManifest {
    pub repository_id: RepositoryId,
    pub snapshot_id: TreeSnapshotId,
    pub projection_id: Option<ProjectionId>,
    pub text_indexes: Vec<TextIndexManifest>,
    pub symbol_indexes: Vec<SymbolIndexManifest>,
    pub vector_indexes: Vec<VectorIndexManifest>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IncrementalIndexPlan {
    pub repository_id: RepositoryId,
    pub base_snapshot_id: Option<TreeSnapshotId>,
    pub next_snapshot_id: TreeSnapshotId,
    pub changed_paths: Vec<String>,
    pub changed_content_hashes: Vec<ContentHash>,
    pub reindex_path_prefixes: Vec<String>,
}

#[async_trait]
pub trait CodeVectorIndex: Send + Sync {
    async fn ensure_index(
        &self,
        repository_id: RepositoryId,
        snapshot_id: TreeSnapshotId,
        chunks: Vec<CodeEmbeddingChunk>,
    ) -> NebulaResult<VectorIndexManifest>;

    async fn search(
        &self,
        manifest_id: VectorIndexManifestId,
        query: &str,
        top_k: usize,
    ) -> NebulaResult<Vec<SemanticSearchHit>>;
}

#[derive(Clone, Debug)]
pub struct PersistedVectorIndex<I, S> {
    inner: I,
    manifest_store: S,
}

impl<I, S> PersistedVectorIndex<I, S> {
    pub fn new(inner: I, manifest_store: S) -> Self {
        Self {
            inner,
            manifest_store,
        }
    }
}

#[async_trait]
impl<I, S> CodeVectorIndex for PersistedVectorIndex<I, S>
where
    I: CodeVectorIndex,
    S: VectorIndexStore,
{
    async fn ensure_index(
        &self,
        repository_id: RepositoryId,
        snapshot_id: TreeSnapshotId,
        chunks: Vec<CodeEmbeddingChunk>,
    ) -> NebulaResult<VectorIndexManifest> {
        let chunks_for_store = chunks.clone();
        let manifest = self
            .inner
            .ensure_index(repository_id, snapshot_id, chunks)
            .await?;
        self.manifest_store.put_manifest(manifest.clone()).await?;
        self.manifest_store
            .put_chunks(&manifest, chunks_for_store)
            .await?;
        Ok(manifest)
    }

    async fn search(
        &self,
        manifest_id: VectorIndexManifestId,
        query: &str,
        top_k: usize,
    ) -> NebulaResult<Vec<SemanticSearchHit>> {
        self.inner.search(manifest_id, query, top_k).await
    }
}

#[async_trait]
pub trait HybridCodeIndex: Send + Sync {
    async fn plan_incremental_index(
        &self,
        repository_id: RepositoryId,
        base_snapshot_id: Option<TreeSnapshotId>,
        next_snapshot_id: TreeSnapshotId,
        changed_paths: Vec<String>,
        changed_content_hashes: Vec<ContentHash>,
    ) -> NebulaResult<IncrementalIndexPlan>;

    async fn ensure_hybrid_index(
        &self,
        plan: IncrementalIndexPlan,
    ) -> NebulaResult<HybridIndexManifest>;

    async fn search_hybrid(
        &self,
        manifest_id: VectorIndexManifestId,
        query: &str,
        top_k: usize,
        policy: RetrievalPolicyContext,
    ) -> NebulaResult<HybridSearchResults>;
}

pub fn draft_manifest(
    repository_id: RepositoryId,
    snapshot_id: TreeSnapshotId,
    config: &VectorIndexConfig,
    chunk_count: u64,
) -> VectorIndexManifest {
    VectorIndexManifest {
        id: VectorIndexManifestId::generated(),
        repository_id,
        snapshot_id,
        projection_id: None,
        index_version: config.index_version.clone(),
        chunk_count,
        embedding_model: config.embedding_model.clone(),
        promoted_at_unix_ms: Some(now_unix_ms()),
        tombstoned_at_unix_ms: None,
    }
}

pub fn tombstone_manifest(
    manifest: &VectorIndexManifest,
    tombstoned_at_unix_ms: u64,
) -> VectorIndexManifest {
    let mut manifest = manifest.clone();
    manifest.tombstoned_at_unix_ms = Some(tombstoned_at_unix_ms);
    manifest
}

#[derive(Clone, Default)]
pub struct InMemoryHybridIndex {
    manifests: Arc<RwLock<BTreeMap<VectorIndexManifestId, VectorIndexManifest>>>,
    chunks: Arc<RwLock<BTreeMap<VectorIndexManifestId, Vec<CodeEmbeddingChunk>>>>,
    text_documents: Arc<RwLock<BTreeMap<VectorIndexManifestId, BTreeMap<String, String>>>>,
    symbols: Arc<RwLock<BTreeMap<VectorIndexManifestId, Vec<SymbolSearchHit>>>>,
    imports: Arc<RwLock<BTreeMap<VectorIndexManifestId, Vec<ImportGraphEdge>>>>,
}

impl InMemoryHybridIndex {
    pub fn ingest_text_documents(
        &self,
        manifest_id: VectorIndexManifestId,
        documents: BTreeMap<String, String>,
    ) -> NebulaResult<()> {
        let symbols = documents
            .iter()
            .flat_map(|(path, content)| extract_symbols(path, content))
            .collect::<Vec<_>>();
        let imports = documents
            .iter()
            .flat_map(|(path, content)| extract_import_edges(path, content))
            .collect::<Vec<_>>();
        self.text_documents
            .write()
            .map_err(|_| nebula_core::NebulaError::Storage("text index lock poisoned".to_string()))?
            .insert(manifest_id.clone(), documents);
        self.symbols
            .write()
            .map_err(|_| {
                nebula_core::NebulaError::Storage("symbol index lock poisoned".to_string())
            })?
            .insert(manifest_id.clone(), symbols);
        self.imports
            .write()
            .map_err(|_| {
                nebula_core::NebulaError::Storage("import graph lock poisoned".to_string())
            })?
            .insert(manifest_id, imports);
        Ok(())
    }
}

#[async_trait]
impl CodeVectorIndex for InMemoryHybridIndex {
    async fn ensure_index(
        &self,
        repository_id: RepositoryId,
        snapshot_id: TreeSnapshotId,
        chunks: Vec<CodeEmbeddingChunk>,
    ) -> NebulaResult<VectorIndexManifest> {
        let config = VectorIndexConfig::default();
        let manifest = draft_manifest(repository_id, snapshot_id, &config, chunks.len() as u64);
        self.manifests
            .write()
            .map_err(|_| {
                nebula_core::NebulaError::Storage("vector manifest lock poisoned".to_string())
            })?
            .insert(manifest.id.clone(), manifest.clone());
        self.chunks
            .write()
            .map_err(|_| {
                nebula_core::NebulaError::Storage("vector chunk lock poisoned".to_string())
            })?
            .insert(manifest.id.clone(), chunks);
        Ok(manifest)
    }

    async fn search(
        &self,
        manifest_id: VectorIndexManifestId,
        query: &str,
        top_k: usize,
    ) -> NebulaResult<Vec<SemanticSearchHit>> {
        let query = query.to_lowercase();
        let chunks = self
            .chunks
            .read()
            .map_err(|_| {
                nebula_core::NebulaError::Storage("vector chunk lock poisoned".to_string())
            })?
            .get(&manifest_id)
            .cloned()
            .unwrap_or_default();
        Ok(chunks
            .into_iter()
            .filter(|chunk| chunk.path.to_lowercase().contains(&query) || query.is_empty())
            .take(top_k)
            .map(|chunk| SemanticSearchHit {
                path: chunk.path,
                start_line: chunk.start_line,
                end_line: chunk.end_line,
                score: 1.0,
                snippet: "experimental in-memory path/hash index hit".to_string(),
            })
            .collect())
    }
}

#[async_trait]
impl HybridCodeIndex for InMemoryHybridIndex {
    async fn plan_incremental_index(
        &self,
        repository_id: RepositoryId,
        base_snapshot_id: Option<TreeSnapshotId>,
        next_snapshot_id: TreeSnapshotId,
        changed_paths: Vec<String>,
        changed_content_hashes: Vec<ContentHash>,
    ) -> NebulaResult<IncrementalIndexPlan> {
        let mut reindex_path_prefixes = changed_paths
            .iter()
            .filter_map(|path| path.split('/').next().map(str::to_string))
            .collect::<Vec<_>>();
        reindex_path_prefixes.sort();
        reindex_path_prefixes.dedup();
        Ok(IncrementalIndexPlan {
            repository_id,
            base_snapshot_id,
            next_snapshot_id,
            changed_paths,
            changed_content_hashes,
            reindex_path_prefixes,
        })
    }

    async fn ensure_hybrid_index(
        &self,
        plan: IncrementalIndexPlan,
    ) -> NebulaResult<HybridIndexManifest> {
        let config = VectorIndexConfig::default();
        let vector_manifest = draft_manifest(
            plan.repository_id.clone(),
            plan.next_snapshot_id.clone(),
            &config,
            plan.changed_paths.len() as u64,
        );
        self.manifests
            .write()
            .map_err(|_| {
                nebula_core::NebulaError::Storage("vector manifest lock poisoned".to_string())
            })?
            .insert(vector_manifest.id.clone(), vector_manifest.clone());
        Ok(HybridIndexManifest {
            repository_id: plan.repository_id.clone(),
            snapshot_id: plan.next_snapshot_id.clone(),
            projection_id: None,
            text_indexes: vec![TextIndexManifest {
                repository_id: plan.repository_id.clone(),
                snapshot_id: plan.next_snapshot_id.clone(),
                projection_id: None,
                shard_key: "root".to_string(),
                index_version: config.index_version.clone(),
                indexed_paths: plan.changed_paths.clone(),
            }],
            symbol_indexes: vec![SymbolIndexManifest {
                repository_id: plan.repository_id,
                snapshot_id: plan.next_snapshot_id,
                projection_id: None,
                shard_key: "root".to_string(),
                index_version: config.index_version,
                symbol_count: 0,
            }],
            vector_indexes: vec![vector_manifest],
        })
    }

    async fn search_hybrid(
        &self,
        manifest_id: VectorIndexManifestId,
        query: &str,
        top_k: usize,
        policy: RetrievalPolicyContext,
    ) -> NebulaResult<HybridSearchResults> {
        let semantic = self
            .search(manifest_id.clone(), query, top_k)
            .await?
            .into_iter()
            .filter(|hit| policy_allows_path(&policy, &hit.path))
            .collect::<Vec<_>>();
        let exact: Vec<ExactTextSearchHit> = semantic
            .iter()
            .map(|hit| ExactTextSearchHit {
                path: hit.path.clone(),
                line: hit.start_line,
                snippet: hit.snippet.clone(),
            })
            .collect();
        let symbols = semantic
            .iter()
            .filter_map(|hit| {
                hit.path.rsplit_once('/').map(|(_, name)| SymbolSearchHit {
                    path: hit.path.clone(),
                    symbol: name.to_string(),
                    kind: SymbolKind::Package,
                    line: hit.start_line,
                })
            })
            .collect();
        let exact = if exact.is_empty() {
            self.text_documents
                .read()
                .map_err(|_| {
                    nebula_core::NebulaError::Storage("text index lock poisoned".to_string())
                })?
                .get(&manifest_id)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .filter(|(path, content)| {
                    policy_allows_path(&policy, path) && text_matches(query, content)
                })
                .take(top_k)
                .map(|(path, content)| ExactTextSearchHit {
                    path,
                    line: matching_line(query, &content),
                    snippet: snippet_for(query, &content),
                })
                .collect()
        } else {
            exact
        };
        let stored_symbols = self
            .symbols
            .read()
            .map_err(|_| {
                nebula_core::NebulaError::Storage("symbol index lock poisoned".to_string())
            })?
            .get(&manifest_id)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter(|hit| {
                policy_allows_path(&policy, &hit.path)
                    && hit.symbol.to_lowercase().contains(&query.to_lowercase())
            })
            .take(top_k)
            .collect::<Vec<_>>();
        let imports = self
            .imports
            .read()
            .map_err(|_| {
                nebula_core::NebulaError::Storage("import graph lock poisoned".to_string())
            })?
            .get(&manifest_id)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter(|edge| {
                policy_allows_path(&policy, &edge.from_path)
                    && edge.imported.to_lowercase().contains(&query.to_lowercase())
            })
            .take(top_k)
            .collect();
        Ok(HybridSearchResults {
            exact,
            symbols: if stored_symbols.is_empty() {
                symbols
            } else {
                stored_symbols
            },
            semantic,
            imports,
        })
    }
}

pub fn policy_allows_path(context: &RetrievalPolicyContext, path: &str) -> bool {
    let engine = PolicyEngine::new(context.policies.clone());
    engine
        .evaluate(&PolicyRequest {
            repository_id: context.repository_id.clone(),
            actor: context.actor.clone(),
            token_id: None,
            environment: None,
            action: PolicyAction::ReadBlob,
            object: PolicyObject::Path(path.to_string()),
            path: Some(path.to_string()),
            key: None,
            service_id: None,
            workspace_id: None,
            sensitivity: None,
            availability: None,
            deploy_source: None,
        })
        .decision
        == PolicyDecision::Allow
}

fn text_matches(query: &str, content: &str) -> bool {
    let query = query.to_lowercase();
    if query.trim().is_empty() {
        return true;
    }
    let content = content.to_lowercase();
    content.contains(&query) || trigrams(&content).iter().any(|gram| query.contains(gram))
}

fn matching_line(query: &str, content: &str) -> Option<u32> {
    let query = query.to_lowercase();
    content
        .lines()
        .position(|line| line.to_lowercase().contains(&query))
        .map(|index| index as u32 + 1)
}

fn snippet_for(query: &str, content: &str) -> String {
    let query = query.to_lowercase();
    content
        .lines()
        .find(|line| line.to_lowercase().contains(&query))
        .unwrap_or_else(|| content.lines().next().unwrap_or_default())
        .trim()
        .to_string()
}

fn trigrams(value: &str) -> Vec<String> {
    value
        .chars()
        .collect::<Vec<_>>()
        .windows(3)
        .map(|chars| chars.iter().collect())
        .collect()
}

fn extract_symbols(path: &str, content: &str) -> Vec<SymbolSearchHit> {
    content
        .lines()
        .enumerate()
        .filter_map(|(index, line)| {
            let trimmed = line.trim_start();
            let (kind, rest) = if let Some(rest) = trimmed.strip_prefix("function ") {
                (SymbolKind::Function, rest)
            } else if let Some(rest) = trimmed.strip_prefix("const ") {
                (SymbolKind::Function, rest)
            } else if let Some(rest) = trimmed.strip_prefix("class ") {
                (SymbolKind::Class, rest)
            } else if let Some(rest) = trimmed.strip_prefix("type ") {
                (SymbolKind::Type, rest)
            } else if let Some(rest) = trimmed.strip_prefix("export ") {
                (SymbolKind::Export, rest)
            } else {
                return None;
            };
            let symbol = rest
                .split(|ch: char| !(ch.is_alphanumeric() || ch == '_' || ch == '$'))
                .next()
                .filter(|value| !value.is_empty())?
                .to_string();
            Some(SymbolSearchHit {
                path: path.to_string(),
                symbol,
                kind,
                line: Some(index as u32 + 1),
            })
        })
        .collect()
}

fn extract_import_edges(path: &str, content: &str) -> Vec<ImportGraphEdge> {
    content
        .lines()
        .enumerate()
        .filter_map(|(index, line)| {
            let trimmed = line.trim();
            let imported = if let Some((_, imported)) = trimmed.split_once(" from ") {
                imported
            } else {
                trimmed.strip_prefix("import ")?
            };
            Some(ImportGraphEdge {
                from_path: path.to_string(),
                imported: imported
                    .trim()
                    .trim_matches(';')
                    .trim_matches('"')
                    .trim_matches('\'')
                    .to_string(),
                line: Some(index as u32 + 1),
            })
        })
        .collect()
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or_default()
}
