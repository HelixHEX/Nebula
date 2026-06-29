use crate::{
    ChangeSet, MergeConflict, MergeConflictKind, MergeState, RefTarget, TreeSnapshot,
    TreeSnapshotId,
};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ThreeWayMergePlan {
    pub state: MergeState,
    pub output_snapshot_id: Option<TreeSnapshotId>,
    pub output_snapshot: Option<TreeSnapshot>,
    pub conflicts: Vec<MergeConflict>,
}

pub fn plan_three_way_merge(
    target_snapshot_id: &TreeSnapshotId,
    changeset: &ChangeSet,
    base: &TreeSnapshot,
    target: &TreeSnapshot,
    proposed: &TreeSnapshot,
) -> ThreeWayMergePlan {
    if target_snapshot_id == &changeset.base_snapshot_id {
        return ThreeWayMergePlan {
            state: MergeState::Merged,
            output_snapshot_id: Some(changeset.next_snapshot_id.clone()),
            output_snapshot: None,
            conflicts: Vec::new(),
        };
    }

    let base_entries = entry_hashes(base);
    let target_entries = entry_hashes(target);
    let proposed_entries = entry_hashes(proposed);
    let target_changed = changed_paths(&base_entries, &target_entries);
    let proposed_changed = changed_paths(&base_entries, &proposed_entries);
    let mut conflicts = Vec::new();

    for path in target_changed.intersection(&proposed_changed) {
        let target_hash = target_entries.get(path);
        let proposed_hash = proposed_entries.get(path);
        if target_hash != proposed_hash {
            conflicts.push(MergeConflict {
                path: path.clone(),
                kind: MergeConflictKind::PathConflict,
                reason: "target and proposal both changed this path".to_string(),
            });
        }
    }

    if conflicts.is_empty() {
        match synthesize_clean_merge(base, target, proposed, &proposed_changed) {
            Ok(snapshot) => ThreeWayMergePlan {
                state: MergeState::Clean,
                output_snapshot_id: Some(snapshot.id.clone()),
                output_snapshot: Some(snapshot),
                conflicts,
            },
            Err(error) => ThreeWayMergePlan {
                state: MergeState::Blocked,
                output_snapshot_id: None,
                output_snapshot: None,
                conflicts: vec![MergeConflict {
                    path: "<merge>".to_string(),
                    kind: MergeConflictKind::PathConflict,
                    reason: error.to_string(),
                }],
            },
        }
    } else {
        ThreeWayMergePlan {
            state: MergeState::Blocked,
            output_snapshot_id: None,
            output_snapshot: None,
            conflicts,
        }
    }
}

pub fn ref_target_snapshot(target: &RefTarget) -> Option<&TreeSnapshotId> {
    match target {
        RefTarget::Snapshot(id) => Some(id),
        _ => None,
    }
}

fn entry_hashes(snapshot: &TreeSnapshot) -> BTreeMap<String, Option<String>> {
    snapshot
        .entries
        .iter()
        .map(|entry| {
            (
                entry.path.clone(),
                entry.hash.as_ref().map(|hash| hash.digest.clone()),
            )
        })
        .collect()
}

fn changed_paths(
    base: &BTreeMap<String, Option<String>>,
    next: &BTreeMap<String, Option<String>>,
) -> BTreeSet<String> {
    let paths = base
        .keys()
        .chain(next.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    paths
        .into_iter()
        .filter(|path| base.get(path) != next.get(path))
        .collect()
}

fn synthesize_clean_merge(
    base: &TreeSnapshot,
    target: &TreeSnapshot,
    proposed: &TreeSnapshot,
    proposed_changed: &BTreeSet<String>,
) -> Result<TreeSnapshot, crate::ModelValidationError> {
    let base_entries = base
        .entries
        .iter()
        .map(|entry| (entry.path.clone(), entry.clone()))
        .collect::<BTreeMap<_, _>>();
    let proposed_entries = proposed
        .entries
        .iter()
        .map(|entry| (entry.path.clone(), entry.clone()))
        .collect::<BTreeMap<_, _>>();
    let mut merged = target
        .entries
        .iter()
        .map(|entry| (entry.path.clone(), entry.clone()))
        .collect::<BTreeMap<_, _>>();
    for path in proposed_changed {
        if let Some(entry) = proposed_entries.get(path) {
            merged.insert(path.clone(), entry.clone());
        } else if base_entries.contains_key(path) {
            merged.remove(path);
        }
    }
    TreeSnapshot::canonical(
        target.repository_id.clone(),
        vec![target.id.clone(), proposed.id.clone()],
        merged.into_values().collect(),
        BTreeMap::new(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Actor, BlobVisibility, ChangeOperation, ChangeOperationKind, ChangeSet, ChangeSetId,
        ContentBlob, RepositoryId, TreeEntry, WorkspaceId,
    };

    fn snapshot(entries: Vec<(&str, &[u8])>) -> TreeSnapshot {
        let repo = RepositoryId::new("repo_test");
        let entries = entries
            .into_iter()
            .map(|(path, bytes)| {
                let blob = ContentBlob::from_bytes(bytes, None, BlobVisibility::Public);
                TreeEntry::file(path, &blob, None).unwrap()
            })
            .collect();
        TreeSnapshot::canonical(repo, Vec::new(), entries, BTreeMap::new()).unwrap()
    }

    fn changeset(base: &TreeSnapshot, next: &TreeSnapshot) -> ChangeSet {
        ChangeSet {
            id: ChangeSetId::new("chg_test"),
            repository_id: base.repository_id.clone(),
            workspace_id: WorkspaceId::new("work_test"),
            base_snapshot_id: base.id.clone(),
            next_snapshot_id: next.id.clone(),
            author: Actor::User("test".to_string()),
            summary: "test".to_string(),
            operations: vec![ChangeOperation {
                path: "proposal.txt".to_string(),
                kind: ChangeOperationKind::Modify,
                before_blob_id: None,
                after_blob_id: None,
                policy_id: None,
            }],
            changed_paths: Vec::new(),
            changed_symbols: Vec::new(),
            changed_packages: Vec::new(),
            affected_targets: Vec::new(),
            affected_tests: Vec::new(),
        }
    }

    #[test]
    fn clean_merge_synthesizes_target_and_proposal_changes() {
        let base = snapshot(vec![("target.txt", b"base"), ("proposal.txt", b"base")]);
        let target = snapshot(vec![("target.txt", b"target"), ("proposal.txt", b"base")]);
        let proposed = snapshot(vec![("target.txt", b"base"), ("proposal.txt", b"proposal")]);
        let changeset = changeset(&base, &proposed);

        let plan = plan_three_way_merge(&target.id, &changeset, &base, &target, &proposed);

        assert_eq!(plan.state, crate::MergeState::Clean);
        let merged = plan.output_snapshot.expect("clean merge snapshot");
        let entries = merged
            .entries
            .iter()
            .map(|entry| {
                (
                    entry.path.as_str(),
                    entry.hash.as_ref().unwrap().digest.as_str(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let target_entries = target
            .entries
            .iter()
            .map(|entry| {
                (
                    entry.path.as_str(),
                    entry.hash.as_ref().unwrap().digest.as_str(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let proposed_entries = proposed
            .entries
            .iter()
            .map(|entry| {
                (
                    entry.path.as_str(),
                    entry.hash.as_ref().unwrap().digest.as_str(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        assert_eq!(entries["target.txt"], target_entries["target.txt"]);
        assert_eq!(entries["proposal.txt"], proposed_entries["proposal.txt"]);
    }

    #[test]
    fn overlapping_edits_block_merge() {
        let base = snapshot(vec![("same.txt", b"base")]);
        let target = snapshot(vec![("same.txt", b"target")]);
        let proposed = snapshot(vec![("same.txt", b"proposal")]);
        let changeset = changeset(&base, &proposed);

        let plan = plan_three_way_merge(&target.id, &changeset, &base, &target, &proposed);

        assert_eq!(plan.state, crate::MergeState::Blocked);
        assert_eq!(plan.conflicts.len(), 1);
    }
}
