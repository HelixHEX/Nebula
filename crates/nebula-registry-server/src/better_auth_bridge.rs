use anyhow::{Context, Result};
use axum::Router;
use better_auth::{
    AuthBuilder, AuthConfig as BetterAuthConfig, AuthRequest, AxumIntegration, BetterAuth,
    HttpMethod, MemoryDatabaseAdapter,
    adapters::SqlxAdapter,
    plugins::{
        AdminPlugin, ApiKeyPlugin, EmailPasswordPlugin, OrganizationPlugin, SessionManagementPlugin,
    },
};
use nebula_core::{Actor, PolicyAction, RepositoryId};
use nebula_registry::{RegistryAuthProvider, VerifiedClaims};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{collections::HashMap, sync::Arc};

use crate::config::ServerConfig;

#[derive(Clone)]
pub struct BetterAuthRegistry {
    pub router: Router,
    pub verifier: Arc<dyn RegistryAuthProvider>,
    verifier_impl: BetterAuthVerifier,
}

#[derive(Clone, Debug)]
pub struct AdminIdentity {
    pub user_id: String,
    pub email: Option<String>,
}

#[derive(Clone)]
enum BetterAuthVerifier {
    Memory(Arc<BetterAuth<MemoryDatabaseAdapter>>),
    Postgres(Arc<BetterAuth<SqlxAdapter>>),
}

pub async fn build(config: &ServerConfig) -> Result<BetterAuthRegistry> {
    if config.dev_mode && config.registry.postgres_url.is_none() {
        let auth = Arc::new(build_memory_auth(config).await?);
        return Ok(BetterAuthRegistry {
            router: auth.clone().axum_router().with_state(auth.clone()),
            verifier: Arc::new(BetterAuthVerifier::Memory(auth.clone())),
            verifier_impl: BetterAuthVerifier::Memory(auth),
        });
    }

    let database_url = config
        .registry
        .postgres_url
        .as_deref()
        .context("DATABASE_URL is required for Better Auth RS")?;
    let auth = Arc::new(build_postgres_auth(config, database_url).await?);
    Ok(BetterAuthRegistry {
        router: auth.clone().axum_router().with_state(auth.clone()),
        verifier: Arc::new(BetterAuthVerifier::Postgres(auth.clone())),
        verifier_impl: BetterAuthVerifier::Postgres(auth),
    })
}

impl BetterAuthRegistry {
    pub async fn verify_admin_bearer(&self, raw_token: &str) -> Result<AdminIdentity, String> {
        self.verifier_impl.verify_admin_identity(raw_token).await
    }
}

async fn build_memory_auth(config: &ServerConfig) -> Result<BetterAuth<MemoryDatabaseAdapter>> {
    AuthBuilder::new(auth_config(config)?)
        .database(MemoryDatabaseAdapter::new())
        .plugin(EmailPasswordPlugin::new())
        .plugin(SessionManagementPlugin::new())
        .plugin(OrganizationPlugin::new())
        .plugin(AdminPlugin::new())
        .plugin(api_key_plugin())
        .build()
        .await
        .map_err(anyhow::Error::msg)
}

async fn build_postgres_auth(
    config: &ServerConfig,
    database_url: &str,
) -> Result<BetterAuth<SqlxAdapter>> {
    let adapter = SqlxAdapter::new(database_url)
        .await
        .context("failed to connect Better Auth RS to Postgres")?;
    AuthBuilder::new(auth_config(config)?)
        .database(adapter)
        .plugin(EmailPasswordPlugin::new())
        .plugin(SessionManagementPlugin::new())
        .plugin(OrganizationPlugin::new())
        .plugin(AdminPlugin::new())
        .plugin(api_key_plugin())
        .build()
        .await
        .map_err(anyhow::Error::msg)
}

fn auth_config(config: &ServerConfig) -> Result<BetterAuthConfig> {
    let secret = config
        .auth_secret
        .clone()
        .context("NEBULA_AUTH_SECRET is required for Better Auth RS")?;
    let base_url = config
        .auth_base_url
        .clone()
        .context("NEBULA_AUTH_BASE_URL is required for Better Auth RS")?;

    Ok(BetterAuthConfig::new(secret)
        .app_name("Nebula Registry")
        .base_url(base_url)
        .base_path("/auth"))
}

fn api_key_plugin() -> ApiKeyPlugin {
    ApiKeyPlugin::builder()
        .prefix("neb_".to_string())
        .enable_metadata(true)
        .enable_session_for_api_keys(true)
        .build()
}

#[async_trait::async_trait]
impl RegistryAuthProvider for BetterAuthVerifier {
    async fn verify_bearer(
        &self,
        raw_token: &str,
        route_repository_id: Option<RepositoryId>,
    ) -> Result<VerifiedClaims, String> {
        match self
            .verify_session(raw_token, route_repository_id.clone())
            .await
        {
            Ok(session) => Ok(session.claims),
            Err(_) => self.verify_api_key(raw_token, route_repository_id).await,
        }
    }
}

impl BetterAuthVerifier {
    async fn verify_admin_identity(&self, raw_token: &str) -> Result<AdminIdentity, String> {
        if let Ok(session) = self.verify_session(raw_token, None).await {
            return Ok(AdminIdentity {
                user_id: session.user_id,
                email: session.email,
            });
        }

        let key = self.verify_api_key_view(raw_token).await?;
        Ok(AdminIdentity {
            user_id: key.user_id,
            email: None,
        })
    }

    async fn verify_session(
        &self,
        raw_token: &str,
        route_repository_id: Option<RepositoryId>,
    ) -> Result<VerifiedSession, String> {
        let mut headers = HashMap::new();
        headers.insert("authorization".to_string(), format!("Bearer {raw_token}"));
        let request = AuthRequest::from_parts(
            HttpMethod::Get,
            "/auth/get-session".to_string(),
            headers,
            None,
            HashMap::new(),
        );
        let response = self.handle(request).await?;
        if response.status != 200 {
            return Err("invalid Better Auth RS session".to_string());
        }
        let body: SessionResponse = serde_json::from_slice(&response.body)
            .map_err(|_| "invalid Better Auth RS session response".to_string())?;
        let user_id = body.user.id;
        let claims = VerifiedClaims {
            actor: Actor::User(user_id.clone()),
            org_id: body.session.active_organization_id,
            repository_id: route_repository_id,
            token_id: None,
            scopes: all_policy_actions(),
        };
        Ok(VerifiedSession {
            user_id,
            email: body.user.email,
            claims,
        })
    }

    async fn verify_api_key(
        &self,
        raw_token: &str,
        route_repository_id: Option<RepositoryId>,
    ) -> Result<VerifiedClaims, String> {
        let key = self.verify_api_key_view(raw_token).await?;
        let org_id = key.org_id();
        let repository_id = key.repository_id().or(route_repository_id);
        Ok(VerifiedClaims {
            actor: Actor::User(key.user_id),
            org_id,
            repository_id,
            token_id: None,
            scopes: policy_actions_from_permissions(key.permissions.as_ref()),
        })
    }

    async fn verify_api_key_view(&self, raw_token: &str) -> Result<ApiKeyView, String> {
        let body = serde_json::to_vec(&json!({ "key": raw_token }))
            .map_err(|_| "failed to encode Better Auth RS API-key verification".to_string())?;
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "application/json".to_string());
        let request = AuthRequest::from_parts(
            HttpMethod::Post,
            "/auth/api-key/verify".to_string(),
            headers,
            Some(body),
            HashMap::new(),
        );
        let response = self.handle(request).await?;
        if response.status != 200 {
            return Err("invalid Better Auth RS API key".to_string());
        }
        let body: VerifyApiKeyResponse = serde_json::from_slice(&response.body)
            .map_err(|_| "invalid Better Auth RS API-key response".to_string())?;
        let Some(key) = body.key.filter(|_| body.valid) else {
            return Err("invalid Better Auth RS API key".to_string());
        };
        Ok(key)
    }

    async fn handle(&self, request: AuthRequest) -> Result<better_auth::AuthResponse, String> {
        match self {
            Self::Memory(auth) => auth.handle_request(request).await,
            Self::Postgres(auth) => auth.handle_request(request).await,
        }
        .map_err(|error| format!("Better Auth RS verification failed: {error}"))
    }
}

#[derive(Deserialize)]
struct SessionResponse {
    session: SessionView,
    user: UserView,
}

struct VerifiedSession {
    user_id: String,
    email: Option<String>,
    claims: VerifiedClaims,
}

#[derive(Deserialize)]
struct SessionView {
    #[serde(rename = "activeOrganizationId")]
    active_organization_id: Option<String>,
}

#[derive(Deserialize)]
struct UserView {
    id: String,
    #[serde(default)]
    email: Option<String>,
}

#[derive(Deserialize)]
struct VerifyApiKeyResponse {
    valid: bool,
    key: Option<ApiKeyView>,
}

#[derive(Deserialize)]
struct ApiKeyView {
    #[serde(rename = "userId")]
    user_id: String,
    permissions: Option<Value>,
    metadata: Option<Value>,
}

impl ApiKeyView {
    fn org_id(&self) -> Option<String> {
        self.metadata
            .as_ref()
            .and_then(|metadata| metadata.get("org_id"))
            .and_then(Value::as_str)
            .map(ToString::to_string)
    }

    fn repository_id(&self) -> Option<RepositoryId> {
        self.metadata
            .as_ref()
            .and_then(|metadata| metadata.get("repository_id"))
            .and_then(Value::as_str)
            .map(RepositoryId::new)
    }
}

fn policy_actions_from_permissions(permissions: Option<&Value>) -> Vec<PolicyAction> {
    let Some(permissions) = permissions else {
        return Vec::new();
    };
    let Some(actions) = permissions
        .get("nebula.repository")
        .or_else(|| permissions.get("nebula"))
        .and_then(Value::as_array)
    else {
        return Vec::new();
    };
    actions
        .iter()
        .filter_map(Value::as_str)
        .filter_map(policy_action_from_str)
        .collect()
}

fn policy_action_from_str(action: &str) -> Option<PolicyAction> {
    match action {
        "read_blob" | "nebula.repository:read_blob" => Some(PolicyAction::ReadBlob),
        "read_path" | "nebula.repository:read_path" => Some(PolicyAction::ReadPath),
        "write_changeset" | "nebula.repository:write_changeset" => {
            Some(PolicyAction::WriteChangeSet)
        }
        "approve_changeset" | "nebula.repository:approve_changeset" => {
            Some(PolicyAction::ApproveChangeSet)
        }
        "merge_changeset" | "nebula.repository:merge_changeset" => {
            Some(PolicyAction::MergeChangeSet)
        }
        "export_git" | "nebula.repository:export_git" => Some(PolicyAction::ExportGit),
        "read_secret" | "nebula.repository:read_secret" => Some(PolicyAction::ReadSecret),
        "inject_secret" | "nebula.repository:inject_secret" => Some(PolicyAction::InjectSecret),
        "read_build_source" | "nebula.repository:read_build_source" => {
            Some(PolicyAction::ReadBuildSource)
        }
        "create_projection" | "nebula.repository:create_projection" => {
            Some(PolicyAction::CreateProjection)
        }
        "deploy" | "nebula.repository:deploy" => Some(PolicyAction::Deploy),
        "manage_auth" | "nebula.repository:manage_auth" => Some(PolicyAction::ManageAuth),
        "manage_webhooks" | "nebula.repository:manage_webhooks" => {
            Some(PolicyAction::ManageWebhooks)
        }
        "sync_objects" | "nebula.repository:sync_objects" => Some(PolicyAction::SyncObjects),
        "review_proposal" | "nebula.repository:review_proposal" => {
            Some(PolicyAction::ReviewProposal)
        }
        "run_status_check" | "nebula.repository:run_status_check" => {
            Some(PolicyAction::RunStatusCheck)
        }
        "index_code" | "nebula.repository:index_code" => Some(PolicyAction::IndexCode),
        _ => None,
    }
}

fn all_policy_actions() -> Vec<PolicyAction> {
    vec![
        PolicyAction::ReadBlob,
        PolicyAction::ReadPath,
        PolicyAction::WriteChangeSet,
        PolicyAction::ApproveChangeSet,
        PolicyAction::MergeChangeSet,
        PolicyAction::ExportGit,
        PolicyAction::ReadSecret,
        PolicyAction::InjectSecret,
        PolicyAction::ReadBuildSource,
        PolicyAction::CreateProjection,
        PolicyAction::Deploy,
        PolicyAction::ManageAuth,
        PolicyAction::ManageWebhooks,
        PolicyAction::SyncObjects,
        PolicyAction::ReviewProposal,
        PolicyAction::RunStatusCheck,
        PolicyAction::IndexCode,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_better_auth_permissions_to_policy_actions() {
        let permissions = json!({
            "nebula.repository": [
                "nebula.repository:read_blob",
                "sync_objects",
                "deploy"
            ]
        });

        let actions = policy_actions_from_permissions(Some(&permissions));

        assert!(actions.contains(&PolicyAction::ReadBlob));
        assert!(actions.contains(&PolicyAction::SyncObjects));
        assert!(actions.contains(&PolicyAction::Deploy));
    }

    #[test]
    fn reads_repository_and_org_binding_from_api_key_metadata() {
        let key = ApiKeyView {
            user_id: "user_1".to_string(),
            permissions: None,
            metadata: Some(json!({
                "org_id": "org_1",
                "repository_id": "repo_1"
            })),
        };

        assert_eq!(key.org_id(), Some("org_1".to_string()));
        assert_eq!(key.repository_id(), Some(RepositoryId::new("repo_1")));
    }
}
