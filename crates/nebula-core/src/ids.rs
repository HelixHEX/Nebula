use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};

macro_rules! id_type {
    ($name:ident, $prefix:literal) => {
        #[derive(
            Clone, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
        )]
        pub struct $name(pub String);

        impl $name {
            pub fn new(raw: impl Into<String>) -> Self {
                Self(raw.into())
            }

            pub fn generated() -> Self {
                Self(format!("{}_{}", $prefix, uuid::Uuid::new_v4().simple()))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl Display for $name {
            fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

id_type!(RepositoryId, "repo");
id_type!(BlobId, "blob");
id_type!(BlobChunkId, "chunk");
id_type!(TreeNodeId, "tree");
id_type!(TreeSnapshotId, "snap");
id_type!(RefId, "ref");
id_type!(WorkspaceId, "work");
id_type!(ChangeSetId, "chg");
id_type!(ProposalId, "prop");
id_type!(MergeIntentId, "merge");
id_type!(ReleaseGateId, "gate");
id_type!(EnvironmentId, "env");
id_type!(PolicyId, "pol");
id_type!(ProjectionId, "proj");
id_type!(DeploymentGrantId, "grant");
id_type!(SecretFileRefId, "secret");
id_type!(VectorIndexManifestId, "vim");
id_type!(VectorIndexJobId, "vjob");
id_type!(GitExportId, "gitexp");
id_type!(GitMigrationRecordId, "gitmig");
id_type!(OperationId, "op");
id_type!(DeployIntentId, "deploy");
id_type!(AuthTokenId, "tok");
id_type!(ReviewCommentId, "comment");
id_type!(StatusCheckId, "check");
id_type!(WebhookEndpointId, "hook");
id_type!(WebhookEventId, "event");
id_type!(SyncSessionId, "sync");

#[derive(
    Clone, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
pub struct ContentHash {
    pub algorithm: String,
    pub digest: String,
}

impl ContentHash {
    pub fn sha256(bytes: &[u8]) -> Self {
        use sha2::{Digest, Sha256};

        let digest = Sha256::digest(bytes);
        Self {
            algorithm: "sha256".to_string(),
            digest: hex::encode(digest),
        }
    }

    pub fn sha256_reader<R: std::io::Read>(reader: R) -> std::io::Result<(Self, u64)> {
        use sha2::{Digest, Sha256};

        let mut reader = std::io::BufReader::new(reader);
        let mut hasher = Sha256::new();
        let mut total_bytes = 0u64;
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let read = std::io::Read::read(&mut reader, &mut buffer)?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
            total_bytes += read as u64;
        }
        Ok((
            Self {
                algorithm: "sha256".to_string(),
                digest: hex::encode(hasher.finalize()),
            },
            total_bytes,
        ))
    }

    pub fn object_path(&self) -> String {
        let prefix = self.digest.get(0..2).unwrap_or("00");
        let shard = self.digest.get(2..4).unwrap_or("00");
        format!(
            "blobs/{}/{}/{}/{}",
            self.algorithm, prefix, shard, self.digest
        )
    }
}

impl BlobId {
    pub fn from_hash(hash: &ContentHash) -> Self {
        Self(format!("{}:{}", hash.algorithm, hash.digest))
    }
}

impl BlobChunkId {
    pub fn from_hash(hash: &ContentHash) -> Self {
        Self(format!("chunk_{}_{}", hash.algorithm, hash.digest))
    }
}

impl TreeNodeId {
    pub fn from_hash(hash: &ContentHash) -> Self {
        Self(format!("tree_{}_{}", hash.algorithm, hash.digest))
    }
}

impl TreeSnapshotId {
    pub fn from_root_hash(hash: &ContentHash) -> Self {
        Self(format!("snap_{}_{}", hash.algorithm, hash.digest))
    }
}
