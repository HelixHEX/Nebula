use nebula_core::{
    BlobId, ContentHash, ModelValidationError, TreeEntry, TreeEntryKind, TreeSnapshot,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::{fs, path::Path};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum OverlayEntry {
    Added { bytes: Vec<u8> },
    Modified { bytes: Vec<u8> },
    Deleted,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct WorkspaceOverlay {
    entries: BTreeMap<String, OverlayEntry>,
    materialized_paths: BTreeSet<String>,
    dirty_paths: BTreeSet<String>,
}

impl WorkspaceOverlay {
    pub fn mark_materialized(&mut self, path: impl Into<String>) {
        self.materialized_paths.insert(path.into());
    }

    pub fn write_file(&mut self, path: impl Into<String>, bytes: Vec<u8>, existed: bool) {
        let path = path.into();
        let entry = if existed {
            OverlayEntry::Modified { bytes }
        } else {
            OverlayEntry::Added { bytes }
        };
        self.materialized_paths.insert(path.clone());
        self.dirty_paths.insert(path.clone());
        self.entries.insert(path, entry);
    }

    pub fn delete_file(&mut self, path: impl Into<String>) {
        let path = path.into();
        self.materialized_paths.insert(path.clone());
        self.dirty_paths.insert(path.clone());
        self.entries.insert(path, OverlayEntry::Deleted);
    }

    pub fn entries(&self) -> &BTreeMap<String, OverlayEntry> {
        &self.entries
    }

    pub fn materialized_paths(&self) -> &BTreeSet<String> {
        &self.materialized_paths
    }

    pub fn dirty_paths(&self) -> &BTreeSet<String> {
        &self.dirty_paths
    }

    pub fn stats(&self) -> WorkspaceOverlayStats {
        WorkspaceOverlayStats {
            materialized_path_count: self.materialized_paths.len(),
            dirty_path_count: self.dirty_paths.len(),
            overlay_entry_count: self.entries.len(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WorkspaceOverlayStats {
    pub materialized_path_count: usize,
    pub dirty_path_count: usize,
    pub overlay_entry_count: usize,
}

pub fn apply_overlay(
    base: &TreeSnapshot,
    overlay: &WorkspaceOverlay,
) -> Result<TreeSnapshot, ModelValidationError> {
    let mut entries: BTreeMap<String, TreeEntry> = base
        .entries
        .iter()
        .cloned()
        .map(|entry| (entry.path.clone(), entry))
        .collect();

    for (path, overlay_entry) in overlay.entries() {
        match overlay_entry {
            OverlayEntry::Deleted => {
                entries.remove(path);
            }
            OverlayEntry::Added { bytes } | OverlayEntry::Modified { bytes } => {
                entries.insert(
                    path.clone(),
                    TreeEntry {
                        path: path.clone(),
                        kind: TreeEntryKind::File,
                        blob_id: None,
                        hash: Some(ContentHash::sha256(bytes)),
                        size_bytes: Some(bytes.len() as u64),
                        policy_id: None,
                    },
                );
            }
        }
    }

    TreeSnapshot::canonical(
        base.repository_id.clone(),
        vec![base.id.clone()],
        entries.into_values().collect(),
        base.metadata.clone(),
    )
}

#[derive(Debug, thiserror::Error)]
pub enum VirtualFsError {
    #[error("path not found: {0}")]
    NotFound(String),
    #[error("path is unsafe: {0}")]
    UnsafePath(String),
    #[error("missing blob bytes for {0}")]
    MissingBlob(BlobId),
    #[error("io error: {0}")]
    Io(String),
}

pub fn read_virtual_file<F>(
    base: &TreeSnapshot,
    overlay: &WorkspaceOverlay,
    path: &str,
    mut load_blob: F,
) -> Result<Vec<u8>, VirtualFsError>
where
    F: FnMut(&BlobId) -> Option<Vec<u8>>,
{
    if let Some(entry) = overlay.entries().get(path) {
        return match entry {
            OverlayEntry::Added { bytes } | OverlayEntry::Modified { bytes } => Ok(bytes.clone()),
            OverlayEntry::Deleted => Err(VirtualFsError::NotFound(path.to_string())),
        };
    }
    let Some(entry) = base.entries.iter().find(|entry| entry.path == path) else {
        return Err(VirtualFsError::NotFound(path.to_string()));
    };
    let Some(blob_id) = &entry.blob_id else {
        return Err(VirtualFsError::NotFound(path.to_string()));
    };
    load_blob(blob_id).ok_or_else(|| VirtualFsError::MissingBlob(blob_id.clone()))
}

pub fn materialize_virtual_workspace<F>(
    base: &TreeSnapshot,
    overlay: &WorkspaceOverlay,
    root: impl AsRef<Path>,
    mut load_blob: F,
) -> Result<Vec<String>, VirtualFsError>
where
    F: FnMut(&BlobId) -> Option<Vec<u8>>,
{
    let root = root.as_ref();
    fs::create_dir_all(root).map_err(io_error)?;
    let snapshot =
        apply_overlay(base, overlay).map_err(|error| VirtualFsError::Io(error.to_string()))?;
    let mut written = Vec::new();
    for entry in snapshot.entries {
        if !matches!(
            entry.kind,
            TreeEntryKind::File | TreeEntryKind::Executable | TreeEntryKind::Symlink
        ) {
            continue;
        }
        let bytes = read_virtual_file(base, overlay, &entry.path, &mut load_blob)?;
        write_safe(root, &entry.path, &bytes)?;
        written.push(entry.path);
    }
    Ok(written)
}

fn write_safe(root: &Path, repo_path: &str, bytes: &[u8]) -> Result<(), VirtualFsError> {
    if repo_path.starts_with('/') || repo_path.split('/').any(|part| part == "..") {
        return Err(VirtualFsError::UnsafePath(repo_path.to_string()));
    }
    let output = root.join(repo_path);
    if !output.starts_with(root) {
        return Err(VirtualFsError::UnsafePath(repo_path.to_string()));
    }
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent).map_err(io_error)?;
    }
    fs::write(output, bytes).map_err(io_error)
}

fn io_error(error: std::io::Error) -> VirtualFsError {
    VirtualFsError::Io(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlay_tracks_dirty_and_materialized_paths() {
        let mut overlay = WorkspaceOverlay::default();
        overlay.mark_materialized("src/read.ts");
        overlay.write_file("src/write.ts", b"hello".to_vec(), false);
        overlay.delete_file("src/delete.ts");

        let stats = overlay.stats();
        assert_eq!(stats.materialized_path_count, 3);
        assert_eq!(stats.dirty_path_count, 2);
        assert_eq!(stats.overlay_entry_count, 2);
    }
}
