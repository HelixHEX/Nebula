use crate::model::{
    ModelValidationError, TreeEntry, TreeNode, TreeNodeEntryTarget, build_tree_nodes,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub enum TreeDiffKind {
    Added,
    Modified,
    Deleted,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct TreeDiffEntry {
    pub path: String,
    pub kind: TreeDiffKind,
}

#[derive(Clone, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct TreeDiff {
    pub entries: Vec<TreeDiffEntry>,
    pub compared_tree_nodes: usize,
    pub skipped_equal_tree_nodes: usize,
}

pub fn diff_entries(
    before: &[TreeEntry],
    after: &[TreeEntry],
) -> Result<TreeDiff, ModelValidationError> {
    let before_nodes = build_tree_nodes(before)?;
    let after_nodes = build_tree_nodes(after)?;
    let before_map = node_map(before_nodes);
    let after_map = node_map(after_nodes);
    let mut diff = TreeDiff::default();
    diff_node("", &before_map, &after_map, &mut diff);
    diff.entries.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(diff)
}

fn node_map(nodes: Vec<TreeNode>) -> BTreeMap<String, TreeNode> {
    nodes
        .into_iter()
        .map(|node| (node.path.clone(), node))
        .collect()
}

fn diff_node(
    path: &str,
    before: &BTreeMap<String, TreeNode>,
    after: &BTreeMap<String, TreeNode>,
    diff: &mut TreeDiff,
) {
    diff.compared_tree_nodes += 1;
    let before_node = before.get(path);
    let after_node = after.get(path);

    match (before_node, after_node) {
        (Some(left), Some(right)) if left.hash == right.hash => {
            diff.skipped_equal_tree_nodes += 1;
        }
        (None, Some(right)) => {
            collect_node_paths(right, TreeDiffKind::Added, after, diff);
        }
        (Some(left), None) => {
            collect_node_paths(left, TreeDiffKind::Deleted, before, diff);
        }
        (Some(left), Some(right)) => {
            let left_entries = entry_map(left);
            let right_entries = entry_map(right);
            let names = left_entries
                .keys()
                .chain(right_entries.keys())
                .cloned()
                .collect::<BTreeSet<_>>();

            for name in names {
                let child_path = join_path(path, &name);
                match (left_entries.get(&name), right_entries.get(&name)) {
                    (Some(left_entry), Some(right_entry))
                        if left_entry.hash == right_entry.hash =>
                    {
                        if matches!(left_entry.target, TreeNodeEntryTarget::Tree(_)) {
                            diff.skipped_equal_tree_nodes += 1;
                        }
                    }
                    (Some(left_entry), Some(right_entry)) => {
                        if matches!(
                            (&left_entry.target, &right_entry.target),
                            (TreeNodeEntryTarget::Tree(_), TreeNodeEntryTarget::Tree(_))
                        ) {
                            diff_node(&child_path, before, after, diff);
                        } else {
                            diff.entries.push(TreeDiffEntry {
                                path: child_path,
                                kind: TreeDiffKind::Modified,
                            });
                        }
                    }
                    (None, Some(right_entry)) => {
                        if let TreeNodeEntryTarget::Tree(_) = right_entry.target {
                            if let Some(node) = after.get(&child_path) {
                                collect_node_paths(node, TreeDiffKind::Added, after, diff);
                            }
                        } else {
                            diff.entries.push(TreeDiffEntry {
                                path: child_path,
                                kind: TreeDiffKind::Added,
                            });
                        }
                    }
                    (Some(left_entry), None) => {
                        if let TreeNodeEntryTarget::Tree(_) = left_entry.target {
                            if let Some(node) = before.get(&child_path) {
                                collect_node_paths(node, TreeDiffKind::Deleted, before, diff);
                            }
                        } else {
                            diff.entries.push(TreeDiffEntry {
                                path: child_path,
                                kind: TreeDiffKind::Deleted,
                            });
                        }
                    }
                    (None, None) => {}
                }
            }
        }
        (None, None) => {}
    }
}

fn collect_node_paths(
    node: &TreeNode,
    kind: TreeDiffKind,
    nodes: &BTreeMap<String, TreeNode>,
    diff: &mut TreeDiff,
) {
    for entry in &node.entries {
        let path = join_path(&node.path, &entry.name);
        match entry.target {
            TreeNodeEntryTarget::Tree(_) => {
                if let Some(child) = nodes.get(&path) {
                    collect_node_paths(child, kind.clone(), nodes, diff);
                }
            }
            TreeNodeEntryTarget::Blob(_) => {
                diff.entries.push(TreeDiffEntry {
                    path,
                    kind: kind.clone(),
                });
            }
        }
    }
}

fn entry_map(node: &TreeNode) -> BTreeMap<String, &crate::model::TreeNodeEntry> {
    node.entries
        .iter()
        .map(|entry| (entry.name.clone(), entry))
        .collect()
}

fn join_path(parent: &str, name: &str) -> String {
    if parent.is_empty() {
        name.to_string()
    } else {
        format!("{parent}/{name}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BlobVisibility, ContentBlob, TreeEntry};

    #[test]
    fn diff_skips_equal_subtrees() {
        let shared = ContentBlob::from_bytes(b"same", None, BlobVisibility::Public);
        let before = ContentBlob::from_bytes(b"before", None, BlobVisibility::Public);
        let after = ContentBlob::from_bytes(b"after", None, BlobVisibility::Public);
        let diff = diff_entries(
            &[
                TreeEntry::file("src/a.ts", &before, None).unwrap(),
                TreeEntry::file("docs/readme.md", &shared, None).unwrap(),
            ],
            &[
                TreeEntry::file("src/a.ts", &after, None).unwrap(),
                TreeEntry::file("docs/readme.md", &shared, None).unwrap(),
            ],
        )
        .unwrap();

        assert_eq!(diff.entries.len(), 1);
        assert_eq!(diff.entries[0].path, "src/a.ts");
        assert!(diff.skipped_equal_tree_nodes >= 1);
    }
}
