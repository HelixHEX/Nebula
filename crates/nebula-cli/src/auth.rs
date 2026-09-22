use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

const KEYRING_SERVICE: &str = "nebula-cli";
const PLAINTEXT_ENV: &str = "NEBULA_AUTH_PLAINTEXT_STORE";
const KEYRING_ENV: &str = "NEBULA_AUTH_KEYRING";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredCredential {
    pub registry_url: String,
    pub token: String,
    #[serde(default)]
    pub org_id: Option<String>,
    #[serde(default)]
    pub repository_id: Option<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct CredentialIndex {
    #[serde(default)]
    registries: BTreeMap<String, CredentialMetadata>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CredentialMetadata {
    org_id: Option<String>,
    #[serde(default)]
    repository_id: Option<String>,
    scopes: Vec<String>,
    storage: CredentialStorage,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum CredentialStorage {
    Keyring,
    Plaintext,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PlaintextCredential {
    token: String,
    metadata: CredentialMetadata,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct PlaintextStore {
    #[serde(default)]
    registries: BTreeMap<String, PlaintextCredential>,
}

pub fn store_credential(credential: StoredCredential) -> Result<CredentialStorageSummary> {
    let registry_key = normalize_registry_url(&credential.registry_url);
    let metadata = CredentialMetadata {
        org_id: credential.org_id,
        repository_id: credential.repository_id,
        scopes: credential.scopes,
        storage: CredentialStorage::Keyring,
    };
    let token = credential.token;

    if keyring_enabled() && !plaintext_enabled() {
        if let Ok(entry) = keyring_entry(&registry_key)
            && entry.set_password(&token).is_ok()
        {
            upsert_index(registry_key.clone(), metadata)?;
            return Ok(CredentialStorageSummary {
                registry_url: registry_key,
                storage: "keyring",
            });
        }
        bail!(
            "could not write the OS keychain entry for {registry_key}; unset {KEYRING_ENV} to use the default secure plaintext store"
        );
    }

    store_plaintext_credential(registry_key, token, metadata)
}

fn store_plaintext_credential(
    registry_key: String,
    token: String,
    mut metadata: CredentialMetadata,
) -> Result<CredentialStorageSummary> {
    let mut plaintext = read_plaintext_store()?;
    metadata.storage = CredentialStorage::Plaintext;
    plaintext.registries.insert(
        registry_key.clone(),
        PlaintextCredential {
            token,
            metadata: metadata.clone(),
        },
    );
    write_plaintext_store(&plaintext)?;
    upsert_index(registry_key.clone(), metadata)?;
    Ok(CredentialStorageSummary {
        registry_url: registry_key,
        storage: "plaintext-dev",
    })
}

pub fn load_credential(registry_url: &str) -> Result<Option<StoredCredential>> {
    let registry_key = normalize_registry_url(registry_url);
    let index = read_index()?;
    let Some(metadata) = index.registries.get(&registry_key).cloned() else {
        return Ok(None);
    };
    let token = match metadata.storage {
        CredentialStorage::Keyring => {
            let entry = keyring_entry(&registry_key)?;
            entry.get_password().with_context(|| {
                format!(
                    "failed to retrieve keychain password for {registry_key}; \
                     re-login without {KEYRING_ENV} set to switch to the default secure plaintext store"
                )
            })?
        }
        CredentialStorage::Plaintext => read_plaintext_store()?
            .registries
            .get(&registry_key)
            .ok_or_else(|| {
                anyhow::anyhow!("plaintext credential for {registry_key} not found in store")
            })?
            .token
            .clone(),
    };
    Ok(Some(StoredCredential {
        registry_url: registry_key,
        token,
        org_id: metadata.org_id,
        repository_id: metadata.repository_id,
        scopes: metadata.scopes,
    }))
}

pub fn delete_credential(registry_url: &str) -> Result<bool> {
    let registry_key = normalize_registry_url(registry_url);
    let mut deleted = false;
    let mut index = read_index()?;
    if let Some(metadata) = index.registries.remove(&registry_key) {
        match metadata.storage {
            CredentialStorage::Keyring => {
                if let Ok(entry) = keyring_entry(&registry_key) {
                    let _ = entry.delete_credential();
                }
            }
            CredentialStorage::Plaintext => {
                let mut plaintext = read_plaintext_store()?;
                plaintext.registries.remove(&registry_key);
                write_plaintext_store(&plaintext)?;
            }
        }
        deleted = true;
    }
    write_index(&index)?;
    Ok(deleted)
}

pub fn list_credentials() -> Result<Vec<StoredCredentialSummary>> {
    let index = read_index()?;
    Ok(index
        .registries
        .into_iter()
        .map(|(registry_url, metadata)| StoredCredentialSummary {
            registry_url,
            org_id: metadata.org_id,
            repository_id: metadata.repository_id,
            scopes: metadata.scopes,
            storage: match metadata.storage {
                CredentialStorage::Keyring => "keyring".to_string(),
                CredentialStorage::Plaintext => "plaintext-dev".to_string(),
            },
        })
        .collect())
}

pub fn normalize_registry_url(url: &str) -> String {
    url.trim().trim_end_matches('/').to_string()
}

#[derive(Clone, Debug, Serialize)]
pub struct CredentialStorageSummary {
    pub registry_url: String,
    pub storage: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct StoredCredentialSummary {
    pub registry_url: String,
    pub org_id: Option<String>,
    pub repository_id: Option<String>,
    pub scopes: Vec<String>,
    pub storage: String,
}

fn keyring_entry(registry_url: &str) -> Result<keyring::Entry> {
    keyring::Entry::new(KEYRING_SERVICE, registry_url).with_context(|| {
        format!(
            "failed to open OS keychain entry for service '{KEYRING_SERVICE}' and account '{registry_url}'"
        )
    })
}

fn keyring_enabled() -> bool {
    std::env::var(KEYRING_ENV)
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "on"))
        .unwrap_or(false)
}

fn plaintext_enabled() -> bool {
    std::env::var(PLAINTEXT_ENV)
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "on"))
        .unwrap_or(false)
}

fn upsert_index(registry_url: String, metadata: CredentialMetadata) -> Result<()> {
    let mut index = read_index()?;
    index.registries.insert(registry_url, metadata);
    write_index(&index)
}

fn read_index() -> Result<CredentialIndex> {
    read_json(&index_path())
}

fn write_index(index: &CredentialIndex) -> Result<()> {
    write_json(&index_path(), index)
}

fn read_plaintext_store() -> Result<PlaintextStore> {
    read_json(&plaintext_path())
}

fn write_plaintext_store(store: &PlaintextStore) -> Result<()> {
    write_json(&plaintext_path(), store)
}

fn read_json<T: for<'de> Deserialize<'de> + Default>(path: &Path) -> Result<T> {
    if !path.exists() {
        return Ok(T::default());
    }
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("failed to parse {}", path.display()))
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let bytes = serde_json::to_vec_pretty(value)?;
    fs::write(path, bytes).with_context(|| format!("failed to write {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("failed to restrict {}", path.display()))?;
    }
    Ok(())
}

fn index_path() -> PathBuf {
    credential_dir().join("credentials.json")
}

fn plaintext_path() -> PathBuf {
    credential_dir().join("credentials.plaintext-dev.json")
}

fn credential_dir() -> PathBuf {
    if let Ok(path) = std::env::var("NEBULA_CREDENTIAL_STORE_DIR") {
        return PathBuf::from(path);
    }
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join(".config")
        .join("nebula")
}
