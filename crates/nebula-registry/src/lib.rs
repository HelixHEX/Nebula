use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use axum::{
    Json, Router,
    body::{Body, Bytes, to_bytes},
    extract::{Extension, Query},
    extract::{Path, State},
    http::{HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode, header},
    middleware::{Next, from_fn_with_state},
    response::{IntoResponse, Response},
    routing::{any, delete, get, post, put},
};
use flate2::{Compression, write::GzEncoder};
use futures::{StreamExt, stream};
use hmac::{Hmac, Mac};
use nebula_auth::{AuthContext, JwksVerifier};
use nebula_core::*;
use nebula_policy::{
    AuthorizationAudit, AuthorizationRequest, CedarNebulaAuthorizer,
    cedar_document_for_visibility_policy, validate_cedar_policy_document,
};
use nebula_storage::{ObjectBlobStore, PgVectorManifestStore, PostgresMetadataStore};
use schemars::{JsonSchema, schema_for};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write,
    path::PathBuf,
    sync::{Arc, RwLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tar::{Builder as TarBuilder, Header as TarHeader};
use tokio::io::AsyncWriteExt;
use tokio_util::io::ReaderStream;

mod import;
pub use import::{ImportFileOptions, ImportFileReport, import_persisted_registry};

const DEFAULT_AUTH_TOKEN_TTL_MS: u64 = 30 * 24 * 60 * 60 * 1_000;
const MAX_AUTH_TOKEN_TTL_MS: u64 = 90 * 24 * 60 * 60 * 1_000;
// Revocation (`neb auth token revoke`) goes straight to the external auth
// provider (Better Auth) and has no hook into this cache, so this TTL is a
// hard upper bound on how long a revoked token keeps working here. Kept
// short (not the request-scoped duration a single sync session could use)
// so revocation reads as "took effect", not "still works for 10 minutes".
const EXTERNAL_AUTH_CACHE_TTL_MS: u64 = 30 * 1_000;
const DIRECT_UPLOAD_URL_TTL_SECONDS: u64 = 15 * 60;

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
pub struct RegistryConfig {
    pub service_name: String,
    pub postgres_url: Option<String>,
    pub blob_store_url: Option<String>,
    pub vector_store_url: Option<String>,
    pub persistence_path: Option<PathBuf>,
    pub auth_required: bool,
    pub auth_issuer: Option<String>,
    pub auth_audience: Option<String>,
    pub auth_jwks_url: Option<String>,
    pub auth_token_authority: AuthTokenAuthority,
    pub public_base_url: Option<String>,
    pub astracollab_deploy_url: Option<String>,
    pub astracollab_deploy_signing_secret: Option<String>,
    pub telemetry_sinks: Vec<String>,
    pub telemetry_event_file: Option<PathBuf>,
    pub telemetry_webhook_url: Option<String>,
    pub telemetry_webhook_secret: Option<String>,
    pub secret_encryption_key: Option<String>,
    pub bootstrap_auth_tokens: Vec<RegistryBootstrapAuthToken>,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
pub struct RegistryBootstrapAuthToken {
    pub name: String,
    pub raw_token: String,
    pub scopes: Vec<PolicyAction>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub enum AuthTokenAuthority {
    AstracollabHosted,
    NebulaSelfHosted,
}

impl Default for RegistryConfig {
    fn default() -> Self {
        Self {
            service_name: "nebula-registry".to_string(),
            postgres_url: None,
            blob_store_url: None,
            vector_store_url: None,
            persistence_path: None,
            auth_required: false,
            auth_issuer: None,
            auth_audience: None,
            auth_jwks_url: None,
            auth_token_authority: AuthTokenAuthority::NebulaSelfHosted,
            public_base_url: None,
            astracollab_deploy_url: None,
            astracollab_deploy_signing_secret: None,
            telemetry_sinks: vec!["json".to_string(), "prometheus".to_string()],
            telemetry_event_file: None,
            telemetry_webhook_url: None,
            telemetry_webhook_secret: None,
            secret_encryption_key: None,
            bootstrap_auth_tokens: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, JsonSchema, Serialize)]
pub struct RegistryHealth {
    pub service: String,
    pub status: String,
}

#[derive(Clone, Debug)]
struct AuthConfig {
    required: bool,
    verifier: Option<JwksVerifier>,
    token_authority: AuthTokenAuthority,
}

impl AuthConfig {
    fn from_registry_config(config: &RegistryConfig) -> Self {
        let verifier = match (
            &config.auth_jwks_url,
            &config.auth_issuer,
            &config.auth_audience,
        ) {
            (Some(jwks_url), Some(issuer), Some(audience)) => Some(JwksVerifier::new(
                jwks_url.clone(),
                issuer.clone(),
                audience.clone(),
            )),
            _ => None,
        };
        Self {
            required: config.auth_required,
            verifier,
            token_authority: config.auth_token_authority.clone(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct VerifiedClaims {
    pub actor: Actor,
    pub org_id: Option<String>,
    pub repository_id: Option<RepositoryId>,
    pub token_id: Option<AuthTokenId>,
    pub scopes: Vec<PolicyAction>,
}

#[async_trait::async_trait]
pub trait RegistryAuthProvider: Send + Sync {
    async fn verify_bearer(
        &self,
        raw_token: &str,
        route_repository_id: Option<RepositoryId>,
    ) -> Result<VerifiedClaims, String>;
}

impl From<AuthContext> for VerifiedClaims {
    fn from(context: AuthContext) -> Self {
        Self {
            actor: context.actor,
            org_id: context.org_id,
            repository_id: context.repository_id,
            token_id: None,
            scopes: context.scopes,
        }
    }
}

async fn auth_middleware(
    State(state): State<AppState>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    let path = request.uri().path();
    if !state.auth.required
        || path == "/health"
        || path == "/health/live"
        || path == "/health/ready"
        || path == "/v1/protocol"
        || path == "/v1/schema"
        || path == "/v2"
        || path == "/v2/"
        || path.starts_with("/v2/")
        || path.starts_with("/v1/deploy-archives/")
    {
        return next.run(request).await;
    }

    let Some(header) = request.headers().get(axum::http::header::AUTHORIZATION) else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "missing Authorization header" })),
        )
            .into_response();
    };
    let Ok(header) = header.to_str() else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "invalid Authorization header" })),
        )
            .into_response();
    };
    let Some(token) = header.strip_prefix("Bearer ").map(str::trim) else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "expected bearer token" })),
        )
            .into_response();
    };

    let route_repository_id = route_repository_id(request.uri().path());

    // Tries the JWKS verifier (if configured), then falls back to a stored
    // API token (bootstrap tokens or a durably-persisted token). Extracted
    // so both the external-auth-provider path below and the no-external-
    // provider path can share it: a bearer token might be *either* kind
    // (e.g. hive-registry runs both a better-auth-rs bridge for its own
    // service tokens AND a JWKS verifier for an external identity provider's
    // end-user tokens — a single `auth_provider` setting used to force an
    // exclusive choice between the two, which broke whichever one wasn't
    // selected).
    async fn verify_via_jwks_or_stored(
        state: &AppState,
        token: &str,
        route_repository_id: Option<&RepositoryId>,
    ) -> Result<VerifiedClaims, String> {
        if let Some(verifier) = &state.auth.verifier
            && let Ok(context) = verifier.verify_token(token).await
        {
            return Ok(context.into());
        }
        if matches!(state.auth.token_authority, AuthTokenAuthority::AstracollabHosted) {
            return Err("hosted Nebula requires configured external auth tokens".to_string());
        }
        verify_stored_api_token(state, token, route_repository_id)
    }

    let verified: VerifiedClaims = if let Some(provider) = &state.external_auth_provider {
        let auth_cache_key = external_auth_cache_key(token, route_repository_id.as_ref());
        let cached = state
            .external_auth_cache
            .read()
            .ok()
            .and_then(|cache| cache.get(&auth_cache_key).cloned())
            .filter(|entry| entry.expires_at_unix_ms > now_unix_ms())
            .map(|entry| entry.claims);
        if let Some(claims) = cached {
            claims
        } else {
            match provider
                .verify_bearer(token, route_repository_id.clone())
                .await
            {
                Ok(claims) => {
                    if let Ok(mut cache) = state.external_auth_cache.write() {
                        cache.insert(
                            auth_cache_key,
                            ExternalAuthCacheEntry {
                                claims: claims.clone(),
                                expires_at_unix_ms: now_unix_ms() + EXTERNAL_AUTH_CACHE_TTL_MS,
                            },
                        );
                    }
                    claims
                }
                Err(_) => {
                    match verify_via_jwks_or_stored(&state, token, route_repository_id.as_ref())
                        .await
                    {
                        Ok(claims) => claims,
                        Err(error) => {
                            return (StatusCode::UNAUTHORIZED, Json(json!({ "error": error })))
                                .into_response();
                        }
                    }
                }
            }
        }
    } else {
        match verify_via_jwks_or_stored(&state, token, route_repository_id.as_ref()).await {
            Ok(claims) => claims,
            Err(error) => {
                return (StatusCode::UNAUTHORIZED, Json(json!({ "error": error }))).into_response();
            }
        }
    };
    if let Err(error) =
        ensure_claims_bound_to_route(&state, &verified, route_repository_id.as_ref())
    {
        if let (Some(repository_id), Some(route)) = (
            route_repository_id.as_ref(),
            route_metadata(request.method(), request.uri().path()),
        ) && let Err(error) = record_denied_authorization_audit(
            &state,
            &verified,
            repository_id,
            route.action.clone(),
            route.resource_kind,
            request.uri().path().to_string(),
            error.clone(),
        )
        .await
        {
            return error.into_response();
        }
        return (StatusCode::FORBIDDEN, Json(json!({ "error": error }))).into_response();
    }
    if let Some(route) = route_metadata(request.method(), request.uri().path()) {
        let required_scope = route.action.clone();
        if !verified.scopes.contains(&required_scope)
            && !verified.scopes.contains(&PolicyAction::ManageAuth)
        {
            if let Some(repository_id) = route_repository_id.as_ref()
                && let Err(error) = record_denied_authorization_audit(
                    &state,
                    &verified,
                    repository_id,
                    required_scope.clone(),
                    route.resource_kind,
                    request.uri().path().to_string(),
                    "token scope does not allow this registry action".to_string(),
                )
                .await
            {
                return error.into_response();
            }
            let required_scope_str = policy_action_scope_str(&required_scope);
            let repo_flag = route_repository_id
                .as_ref()
                .map(|id| format!(" --repository {id}"))
                .unwrap_or_default();
            let hint = if required_scope == PolicyAction::ManageAuth {
                "manage_auth bypasses per-repository policy checks, so it's never \
                 self-issuable via `neb auth token create` (on registries using \
                 Nebula-owned tokens this is enforced server-side; on Better Auth \
                 deployments it depends on your account's own Better Auth \
                 permissions, not this registry). Use `neb auth login` with an \
                 existing credential that already carries it, or ask an admin to \
                 grant your account access."
                    .to_string()
            } else {
                format!(
                    "this token doesn't have the '{required_scope_str}' scope; mint one with: neb auth token create <name>{repo_flag} --scope nebula.repository:{required_scope_str}"
                )
            };
            return (
                StatusCode::FORBIDDEN,
                Json(json!({
                    "error": "token scope does not allow this registry action",
                    "required_scope": required_scope_str,
                    "hint": hint,
                })),
            )
                .into_response();
        }
        if let Some(repository_id) = route_repository_id {
            let (policies, cedar_documents) = match state.registry.read() {
                Ok(registry) => {
                    let policies = registry.policies.values().cloned().collect::<Vec<_>>();
                    let cedar_documents = registry
                        .cedar_policy_documents
                        .values()
                        .filter(|document| {
                            document.enabled && document.repository_id == repository_id
                        })
                        .map(|document| nebula_policy::CedarPolicyDocument {
                            id: document.id.clone(),
                            repository_id: document.repository_id.clone(),
                            text: document.text.clone(),
                            version: document.version,
                            enabled: document.enabled,
                        })
                        .collect::<Vec<_>>();
                    (policies, cedar_documents)
                }
                Err(_) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({ "error": "registry lock poisoned" })),
                    )
                        .into_response();
                }
            };
            let authorizer = CedarNebulaAuthorizer::with_cedar_documents(policies, cedar_documents);
            let authorization_request = AuthorizationRequest {
                actor: verified.actor.clone(),
                token_id: verified.token_id.clone(),
                action: required_scope,
                repository_id: repository_id.clone(),
                resource_kind: route.resource_kind.to_string(),
                resource_id: request.uri().path().to_string(),
                path: Some(request.uri().path().to_string()),
                environment: None,
            };
            let authorization_result = authorizer.authorize(authorization_request.clone());
            if let Ok(audit) = &authorization_result
                && let Err(error) = record_authorization_audit(&state, audit).await
            {
                return error.into_response();
            }
            if authorization_result.is_err() && !verified.scopes.contains(&PolicyAction::ManageAuth)
            {
                let audit = AuthorizationAudit {
                    actor: authorization_request.actor,
                    action: authorization_request.action,
                    repository_id: authorization_request.repository_id,
                    resource_kind: authorization_request.resource_kind,
                    resource_id: authorization_request.resource_id,
                    path: authorization_request.path,
                    environment: authorization_request.environment,
                    decision: PolicyDecision::Block,
                    reason: "policy denied this registry action".to_string(),
                    engine: "cedar-policy",
                    matched_policy_ids: Vec::new(),
                    timestamp_unix_ms: now_unix_ms(),
                };
                if let Err(error) = record_authorization_audit(&state, &audit).await {
                    return error.into_response();
                }
                let mut attributes = BTreeMap::new();
                attributes.insert("resource_kind".to_string(), json!(audit.resource_kind));
                attributes.insert("resource_id".to_string(), json!(audit.resource_id));
                attributes.insert("action".to_string(), json!(format!("{:?}", audit.action)));
                emit_telemetry_event(
                    state.clone(),
                    telemetry_event(
                        "auth.policy.denied",
                        TelemetrySource::Auth,
                        TelemetrySeverity::Warning,
                        "policy denied registry action",
                        NebulaTelemetryContext {
                            repository_id: Some(repository_id),
                            ..Default::default()
                        },
                        attributes,
                    ),
                );
                let action_str = policy_action_scope_str(&audit.action);
                let actor_str = actor_cli_spec(&audit.actor);
                let token_flag = authorization_request
                    .token_id
                    .as_ref()
                    .map(|token_id| format!(" --token {token_id}"))
                    .unwrap_or_default();
                let hint = format!(
                    "no policy allows {actor_str} to {action_str} on {}; grant it with: neb galaxy policy grant {} {actor_str} --action {action_str}{token_flag}",
                    audit.repository_id, audit.repository_id
                );
                let hint = if token_flag.is_empty() {
                    hint
                } else {
                    format!(
                        "{hint} (add {token_flag} to scope this grant to just this token; omit it to grant the whole account)"
                    )
                };
                return (
                    StatusCode::FORBIDDEN,
                    Json(json!({
                        "error": "policy denied this registry action",
                        "actor": actor_str,
                        "required_action": action_str,
                        "hint": hint,
                    })),
                )
                    .into_response();
            }
        }
    } else if is_protected_registry_path(request.uri().path()) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "route is missing authorization metadata" })),
        )
            .into_response();
    }
    request.extensions_mut().insert(verified);
    next.run(request).await
}

/// Converts a `PolicyAction` variant (e.g. `ManageDeployConfig`) into the
/// snake_case scope string used on the wire and in `--scope`/`--action`
/// flags (e.g. "manage_deploy_config"), for building actionable error hints.
fn policy_action_scope_str(action: &PolicyAction) -> String {
    let debug = format!("{action:?}");
    let mut result = String::new();
    for (index, ch) in debug.chars().enumerate() {
        if ch.is_uppercase() && index > 0 {
            result.push('_');
        }
        result.extend(ch.to_lowercase());
    }
    result
}

/// Formats an `Actor` as the CLI's "<kind>:<id>" spec (or "public"), so it
/// can be pasted directly into `neb galaxy policy grant`.
fn actor_cli_spec(actor: &Actor) -> String {
    match actor {
        Actor::User(id) => format!("user:{id}"),
        Actor::Team(id) => format!("team:{id}"),
        Actor::Agent(id) => format!("agent:{id}"),
        Actor::Integration(id) => format!("integration:{id}"),
        Actor::Public => "public".to_string(),
    }
}

fn route_repository_id(path: &str) -> Option<RepositoryId> {
    let mut parts = path.split('/').filter(|part| !part.is_empty());
    while let Some(part) = parts.next() {
        if part == "galaxies" {
            let next = parts.next()?;
            if next == "by-name" {
                return None;
            }
            return Some(RepositoryId::new(next));
        }
    }
    None
}

fn is_protected_registry_path(path: &str) -> bool {
    path.starts_with("/v1/galaxies")
}

fn verify_stored_api_token(
    state: &AppState,
    raw_token: &str,
    route_repository_id: Option<&RepositoryId>,
) -> Result<VerifiedClaims, String> {
    let now = now_unix_ms();
    let presented_hash = ContentHash::sha256(raw_token.as_bytes()).digest;
    let registry = state
        .registry
        .read()
        .map_err(|_| "registry lock poisoned".to_string())?;
    let token = registry
        .auth_tokens
        .values()
        .find(|candidate| {
            constant_time_eq(candidate.token_hash.as_bytes(), presented_hash.as_bytes())
        })
        .ok_or_else(|| "invalid bearer token".to_string())?;
    if token.revoked_at_unix_ms.is_some() {
        return Err("bearer token has been revoked".to_string());
    }
    if token
        .expires_at_unix_ms
        .is_some_and(|expires_at| expires_at <= now)
    {
        return Err("bearer token has expired".to_string());
    }
    if let (Some(route_repository_id), Some(token_repository_id)) =
        (route_repository_id, token.repository_id.as_ref())
        && route_repository_id != token_repository_id
    {
        return Err("bearer token is not scoped to this repository".to_string());
    }
    Ok(VerifiedClaims {
        actor: token.actor.clone(),
        org_id: token.org_id.clone(),
        repository_id: token.repository_id.clone(),
        token_id: Some(token.id.clone()),
        scopes: token.scopes.clone(),
    })
}

fn ensure_claims_bound_to_route(
    state: &AppState,
    claims: &VerifiedClaims,
    route_repository_id: Option<&RepositoryId>,
) -> Result<(), String> {
    let Some(route_repository_id) = route_repository_id else {
        return Ok(());
    };
    if claims
        .repository_id
        .as_ref()
        .is_some_and(|claim_repository_id| claim_repository_id != route_repository_id)
    {
        return Err("bearer token repository claim does not match route".to_string());
    }
    if let Some(claim_org_id) = &claims.org_id {
        let registry = state
            .registry
            .read()
            .map_err(|_| "registry lock poisoned".to_string())?;
        if let Some(repository) = registry.repositories.get(route_repository_id)
            && repository
                .org_id
                .as_ref()
                .is_some_and(|repository_org_id| repository_org_id != claim_org_id)
        {
            return Err("bearer token organization claim does not match repository".to_string());
        }
    }
    Ok(())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |acc, (left, right)| acc | (left ^ right))
        == 0
}

#[derive(Clone, Debug)]
struct RouteMetadata {
    action: PolicyAction,
    resource_kind: &'static str,
}

fn route_metadata(method: &Method, path: &str) -> Option<RouteMetadata> {
    let segments = path
        .split('/')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    let action = match segments.as_slice() {
        ["v1", "galaxies"] if method == Method::GET => PolicyAction::ReadBlob,
        ["v1", "galaxies"] => PolicyAction::ManageAuth,
        ["v1", "galaxies", "by-name", _, _] => PolicyAction::ReadBlob,
        ["v1", "galaxies", _] => PolicyAction::ReadBlob,
        ["v1", "galaxies", _, "auth-tokens"] | ["v1", "galaxies", _, "operations"] => {
            PolicyAction::ManageAuth
        }
        ["v1", "galaxies", _, "webhook-endpoints"] | ["v1", "galaxies", _, "webhook-events"] => {
            PolicyAction::ManageWebhooks
        }
        ["v1", "galaxies", _, "vector-index-jobs"]
        | ["v1", "galaxies", _, "vector-manifests"]
        | ["v1", "galaxies", _, "vector-indexes"]
        | ["v1", "galaxies", _, "vector-search"]
        | ["v1", "galaxies", _, "vector-explain"] => PolicyAction::IndexCode,
        ["v1", "galaxies", _, "proposal-comments"] => PolicyAction::ReviewProposal,
        ["v1", "galaxies", _, "proposal-checks"] => PolicyAction::RunStatusCheck,
        ["v1", "galaxies", _, "sync-sessions"]
        | ["v1", "galaxies", _, "sync-sessions", ..]
        | ["v1", "galaxies", _, "blobs", "batch"]
        | ["v1", "galaxies", _, "trees", "batch"]
        | ["v1", "galaxies", _, "sync-bundle"] => PolicyAction::SyncObjects,
        ["v1", "galaxies", _, "build-projections"] => PolicyAction::ReadBuildSource,
        ["v1", "galaxies", _, "projections"] => PolicyAction::CreateProjection,
        ["v1", "galaxies", _, "git-exports"] => PolicyAction::ExportGit,
        ["v1", "galaxies", _, "deployment-grants"]
        | ["v1", "galaxies", _, "deploy-intents"]
        | ["v1", "galaxies", _, "deploy-intents", _, "status"]
        | ["v1", "galaxies", _, "release-gates"] => PolicyAction::Deploy,
        ["v1", "galaxies", _, "environments", _, "variables"] if method == Method::GET => {
            PolicyAction::ReadVariableMetadata
        }
        ["v1", "galaxies", _, "environments", _, "variables"] => PolicyAction::ManageVariables,
        [
            "v1",
            "galaxies",
            _,
            "environments",
            _,
            "variables",
            "inject",
        ] => PolicyAction::InjectVariable,
        [
            "v1",
            "galaxies",
            _,
            "environments",
            _,
            "variables",
            _,
            "export",
        ] => PolicyAction::ExportSecret,
        ["v1", "galaxies", _, "environments"] if method == Method::GET => {
            PolicyAction::ReadBuildSource
        }
        ["v1", "galaxies", _, "policies"]
        | ["v1", "galaxies", _, "policies", _]
        | ["v1", "galaxies", _, "cedar-policies"]
        | ["v1", "galaxies", _, "integrations"]
        | ["v1", "galaxies", _, "environments"] => PolicyAction::ManageAuth,
        // Deploy-config registration (pointing a service's deploy-intent
        // webhook at e.g. Horizon) is a narrower, self-service-friendly
        // action than the other admin routes above: it doesn't need the
        // ManageAuth bypass scope, which self-issued tokens are deliberately
        // not allowed to hold.
        ["v1", "galaxies", _, "deploy-configs", ..] => PolicyAction::ManageDeployConfig,
        ["v1", "galaxies", _, "merge-intents"] => PolicyAction::MergeChangeSet,
        ["v1", "galaxies", _, "refs", ..] => PolicyAction::MergeChangeSet,
        ["v1", "galaxies", _, "proposals"] | ["v1", "galaxies", _, "proposals", _] => {
            PolicyAction::ReviewProposal
        }
        ["v1", "galaxies", _, "changesets"]
        | ["v1", "galaxies", _, "changesets", _]
        | ["v1", "galaxies", _, "snapshots"]
        | ["v1", "galaxies", _, "snapshots", _]
        | ["v1", "galaxies", _, "snapshots", _, "tree"]
        | ["v1", "galaxies", _, "workspaces"] => PolicyAction::WriteChangeSet,
        ["v1", "galaxies", _, "blobs", ..] if method == Method::GET => PolicyAction::ReadBlob,
        ["v1", "galaxies", _, "blobs"] => PolicyAction::WriteChangeSet,
        _ => return None,
    };
    Some(RouteMetadata {
        action,
        resource_kind: route_resource_kind_without_metadata(path),
    })
}

fn route_resource_kind_without_metadata(path: &str) -> &'static str {
    if path.contains("/auth-tokens") {
        "AuthToken"
    } else if path.contains("/webhook-") {
        "Webhook"
    } else if path.contains("/sync-sessions") || path.contains("/sync-bundle") {
        "SyncSession"
    } else if path.contains("/variables") {
        "EnvironmentVariable"
    } else if path.contains("/release-gates") {
        "ReleaseGate"
    } else if path.contains("/deploy-intents") {
        "DeployIntent"
    } else if path.contains("/deployment-grants") {
        "DeploymentGrant"
    } else if path.contains("/build-projections") {
        "BuildSource"
    } else if path.contains("/cedar-policies") {
        "CedarPolicyDocument"
    } else if path.contains("/blobs") {
        "Blob"
    } else if path.contains("/snapshots") || path.contains("/trees") {
        "Snapshot"
    } else if path.contains("/refs") {
        "Ref"
    } else if path.contains("/workspaces") {
        "Workspace"
    } else if path.contains("/changesets") {
        "ChangeSet"
    } else if path.contains("/proposals") || path.contains("/proposal-") {
        "Proposal"
    } else if path.contains("/projections") {
        "Projection"
    } else if path.contains("/git-exports") {
        "GitExport"
    } else if path.contains("/vector") {
        "VectorJob"
    } else {
        "Galaxy"
    }
}

pub fn router(config: RegistryConfig) -> Router {
    let registry = load_registry_from_persistence(config.persistence_path.as_ref())
        .unwrap_or_else(|error| panic!("{error}"));
    router_with_state(config, registry)
}

pub async fn router_async(config: RegistryConfig) -> Result<Router, String> {
    router_async_with_auth_provider(config, None).await
}

pub async fn router_async_with_auth_provider(
    config: RegistryConfig,
    external_auth_provider: Option<Arc<dyn RegistryAuthProvider>>,
) -> Result<Router, String> {
    let mut registry = load_registry_from_persistence(config.persistence_path.as_ref())?;
    let durable_store = match &config.postgres_url {
        Some(url) => Some(Arc::new(
            PostgresMetadataStore::connect(url)
                .await
                .map_err(|error| error.to_string())?,
        ) as Arc<dyn RegistryStore>),
        None => None,
    };
    if let Some(store) = &durable_store {
        hydrate_registry_from_store(store.as_ref(), &mut registry)
            .await
            .map_err(|error| error.message)?;
    }
    let object_blob_store = match &config.blob_store_url {
        Some(url) => Some(Arc::new(
            ObjectBlobStore::from_url(url).map_err(|error| error.to_string())?,
        )),
        None => None,
    };
    let blob_store = object_blob_store
        .as_ref()
        .map(|store| store.clone() as Arc<dyn BlobStore>);
    let vector_store = match &config.vector_store_url {
        Some(url) => Some(Arc::new(
            PgVectorManifestStore::connect(url)
                .await
                .map_err(|error| error.to_string())?,
        ) as Arc<dyn VectorIndexStore>),
        None => None,
    };
    Ok(router_with_backend(
        config,
        registry,
        durable_store,
        blob_store,
        object_blob_store,
        vector_store,
        external_auth_provider,
    ))
}

pub fn router_with_state(config: RegistryConfig, registry: InMemoryRegistry) -> Router {
    router_with_backend(config, registry, None, None, None, None, None)
}

fn router_with_backend(
    config: RegistryConfig,
    mut registry: InMemoryRegistry,
    durable_store: Option<Arc<dyn RegistryStore>>,
    blob_store: Option<Arc<dyn BlobStore>>,
    object_blob_store: Option<Arc<ObjectBlobStore>>,
    vector_store: Option<Arc<dyn VectorIndexStore>>,
    external_auth_provider: Option<Arc<dyn RegistryAuthProvider>>,
) -> Router {
    let service_name = config.service_name.clone();
    apply_bootstrap_auth_tokens(&mut registry, &config.bootstrap_auth_tokens);
    let state = AppState {
        registry: Arc::new(RwLock::new(registry)),
        persistence_path: config.persistence_path.clone(),
        auth: AuthConfig::from_registry_config(&config),
        external_auth_provider,
        external_auth_cache: Arc::new(RwLock::new(BTreeMap::new())),
        durable_store,
        blob_store,
        object_blob_store,
        vector_store,
        public_base_url: config.public_base_url.clone(),
        astracollab_deploy_url: config.astracollab_deploy_url.clone(),
        astracollab_deploy_signing_secret: config.astracollab_deploy_signing_secret.clone(),
        deploy_archive_cache: Arc::new(RwLock::new(BTreeMap::new())),
        telemetry_sinks: config.telemetry_sinks.clone(),
        telemetry_event_file: config.telemetry_event_file.clone(),
        telemetry_webhook_url: config.telemetry_webhook_url.clone(),
        telemetry_webhook_secret: config.telemetry_webhook_secret.clone(),
        secret_encryption_key: config.secret_encryption_key.clone(),
        http_client: reqwest::Client::new(),
    };

    Router::new()
        .route(
            "/health",
            get(move || {
                let service = service_name.clone();
                async move {
                    Json(RegistryHealth {
                        service,
                        status: "ok".to_string(),
                    })
                }
            }),
        )
        .route("/health/live", get(health_live))
        .route("/health/ready", get(health_ready))
        .route("/v2", any(oci_v2_root))
        .route("/v2/", any(oci_v2_root))
        .route("/v2/{*path}", any(oci_dispatch))
        .route("/v1/protocol", get(protocol))
        .route("/v1/schema", get(schema))
        .route("/v1/whoami", get(whoami))
        .route(
            "/v1/deploy-archives/{repository_id}/{intent_id}",
            get(get_deploy_archive),
        )
        .route("/v1/galaxies", get(list_galaxies).post(create_repository))
        .route("/v1/galaxies/{repository_id}", get(get_repository))
        .route(
            "/v1/galaxies/by-name/{owner}/{name}",
            get(get_repository_by_name),
        )
        .route("/v1/galaxies/{repository_id}/blobs", put(put_blob))
        .route(
            "/v1/galaxies/{repository_id}/blobs/{algorithm}/{digest}",
            get(get_blob),
        )
        .route(
            "/v1/galaxies/{repository_id}/blobs/batch",
            post(get_blobs_batch),
        )
        .route(
            "/v1/galaxies/{repository_id}/blobs/{algorithm}/{digest}/chunks",
            get(get_blob_chunks),
        )
        .route("/v1/galaxies/{repository_id}/snapshots", put(put_snapshot))
        .route(
            "/v1/galaxies/{repository_id}/snapshots/{snapshot_id}",
            get(get_snapshot),
        )
        .route(
            "/v1/galaxies/{repository_id}/snapshots/{snapshot_id}/tree",
            get(get_snapshot_tree),
        )
        .route(
            "/v1/galaxies/{repository_id}/trees/batch",
            post(get_trees_batch),
        )
        .route("/v1/galaxies/{repository_id}/refs", put(put_ref))
        .route("/v1/galaxies/{repository_id}/refs/{name}", get(get_ref))
        .route(
            "/v1/galaxies/{repository_id}/workspaces",
            post(create_workspace),
        )
        .route(
            "/v1/galaxies/{repository_id}/changesets",
            put(put_changeset),
        )
        .route(
            "/v1/galaxies/{repository_id}/changesets/{changeset_id}",
            get(get_changeset),
        )
        .route(
            "/v1/galaxies/{repository_id}/proposals",
            post(create_proposal),
        )
        .route(
            "/v1/galaxies/{repository_id}/proposals/{proposal_id}",
            get(get_proposal),
        )
        .route(
            "/v1/galaxies/{repository_id}/policies",
            get(list_policies).put(put_policy),
        )
        .route(
            "/v1/galaxies/{repository_id}/policies/{policy_id}",
            delete(delete_policy),
        )
        .route(
            "/v1/galaxies/{repository_id}/cedar-policies",
            put(put_cedar_policy_document),
        )
        .route(
            "/v1/galaxies/{repository_id}/environments",
            get(list_environments).put(put_environment),
        )
        .route(
            "/v1/galaxies/{repository_id}/environments/{environment_id}/variables",
            get(list_environment_variables).put(upsert_environment_variable),
        )
        .route(
            "/v1/galaxies/{repository_id}/environments/{environment_id}/variables/inject",
            post(inject_environment_variables),
        )
        .route(
            "/v1/galaxies/{repository_id}/environments/{environment_id}/variables/{variable_id}/export",
            post(export_environment_variable),
        )
        .route(
            "/v1/galaxies/{repository_id}/integrations",
            put(put_integration),
        )
        .route(
            "/v1/galaxies/{repository_id}/merge-intents",
            put(put_merge_intent),
        )
        .route(
            "/v1/galaxies/{repository_id}/release-gates",
            put(put_release_gate),
        )
        .route(
            "/v1/galaxies/{repository_id}/vector-manifests",
            put(put_vector_manifest),
        )
        .route(
            "/v1/galaxies/{repository_id}/vector-indexes",
            post(create_vector_index),
        )
        .route(
            "/v1/galaxies/{repository_id}/vector-search",
            post(search_vector_index),
        )
        .route(
            "/v1/galaxies/{repository_id}/vector-explain",
            post(explain_vector_chunk),
        )
        .route(
            "/v1/galaxies/{repository_id}/projections",
            put(put_projection),
        )
        .route(
            "/v1/galaxies/{repository_id}/git-exports",
            put(put_git_export),
        )
        .route(
            "/v1/galaxies/{repository_id}/operations",
            put(put_operation),
        )
        .route(
            "/v1/galaxies/{repository_id}/deployment-grants",
            put(put_deployment_grant),
        )
        .route(
            "/v1/galaxies/{repository_id}/deploy-configs/{*service_id}",
            get(get_deploy_config)
                .put(put_deploy_config)
                .delete(delete_deploy_config),
        )
        .route(
            "/v1/galaxies/{repository_id}/deploy-intents",
            post(create_deploy_intent),
        )
        .route(
            "/v1/galaxies/{repository_id}/deploy-intents/{intent_id}",
            get(get_deploy_intent),
        )
        .route(
            "/v1/galaxies/{repository_id}/deploy-intents/{intent_id}/status",
            post(update_deploy_intent_status),
        )
        .route(
            "/v1/galaxies/{repository_id}/build-projections",
            post(create_build_projection),
        )
        .route(
            "/v1/galaxies/{repository_id}/auth-tokens",
            put(put_auth_token),
        )
        .route(
            "/v1/galaxies/{repository_id}/proposal-comments",
            put(put_proposal_comment),
        )
        .route(
            "/v1/galaxies/{repository_id}/proposal-checks",
            put(put_proposal_check),
        )
        .route(
            "/v1/galaxies/{repository_id}/webhook-endpoints",
            put(put_webhook_endpoint),
        )
        .route(
            "/v1/galaxies/{repository_id}/webhook-events",
            put(put_webhook_event),
        )
        .route(
            "/v1/galaxies/{repository_id}/sync-sessions",
            post(start_sync_session).put(put_sync_session),
        )
        .route(
            "/v1/galaxies/{repository_id}/sync-sessions/{session_id}",
            get(get_sync_session),
        )
        .route(
            "/v1/galaxies/{repository_id}/sync-sessions/{session_id}/chunks",
            put(put_sync_session_chunks),
        )
        .route(
            "/v1/galaxies/{repository_id}/sync-sessions/{session_id}/bundle",
            put(put_sync_session_bundle),
        )
        .route(
            "/v1/galaxies/{repository_id}/sync-sessions/{session_id}/missing-blobs",
            post(get_missing_sync_session_blobs),
        )
        .route(
            "/v1/galaxies/{repository_id}/sync-sessions/{session_id}/blob-uploads/batch",
            post(plan_sync_session_blob_uploads),
        )
        .route(
            "/v1/galaxies/{repository_id}/sync-sessions/{session_id}/blob-uploads/confirm",
            post(confirm_sync_session_blob_uploads),
        )
        .route(
            "/v1/galaxies/{repository_id}/sync-sessions/{session_id}/blob-pack",
            put(put_sync_session_blob_pack),
        )
        .route(
            "/v1/galaxies/{repository_id}/sync-sessions/{session_id}/chunks/{chunk_id}",
            get(get_sync_session_chunk).put(put_sync_session_chunk),
        )
        .route(
            "/v1/galaxies/{repository_id}/sync-sessions/{session_id}/blobs/{algorithm}/{digest}",
            get(get_sync_session_blob).put(put_sync_session_blob),
        )
        .route(
            "/v1/galaxies/{repository_id}/sync-sessions/{session_id}/validate",
            post(validate_sync_session),
        )
        .route(
            "/v1/galaxies/{repository_id}/sync-sessions/{session_id}/commit",
            post(commit_sync_session),
        )
        .route(
            "/v1/galaxies/{repository_id}/sync-sessions/{session_id}/abort",
            post(abort_sync_session),
        )
        .route(
            "/v1/galaxies/{repository_id}/sync-bundle",
            get(get_sync_bundle).put(put_sync_bundle),
        )
        .route(
            "/v1/galaxies/{repository_id}/vector-index-jobs",
            put(put_vector_index_job),
        )
        .with_state(state.clone())
        .layer(from_fn_with_state(state, auth_middleware))
}

async fn protocol() -> Json<RegistryProtocol> {
    Json(RegistryProtocol::default())
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
pub struct WhoAmIResponse {
    pub actor: Actor,
    pub org_id: Option<String>,
    pub repository_id: Option<RepositoryId>,
    pub token_id: Option<AuthTokenId>,
    pub scopes: Vec<PolicyAction>,
    /// True if this identity's scopes bypass per-repository policy checks
    /// (see `ManageAuth`). Useful for telling whether `neb galaxy policy
    /// grant` is even necessary for this identity to act.
    pub bypasses_policy_checks: bool,
}

/// Returns the caller's own resolved identity: which `Actor` their bearer
/// token maps to, and what scopes/repository binding it carries. Exists so
/// `neb galaxy policy grant` doesn't require guessing what actor string to
/// grant — for a token's owning account, that's usually `user:<user_id>`,
/// not the token's display name.
async fn whoami(Extension(claims): Extension<VerifiedClaims>) -> Json<WhoAmIResponse> {
    let bypasses_policy_checks = claims.scopes.contains(&PolicyAction::ManageAuth);
    Json(WhoAmIResponse {
        actor: claims.actor,
        org_id: claims.org_id,
        repository_id: claims.repository_id,
        token_id: claims.token_id,
        scopes: claims.scopes,
        bypasses_policy_checks,
    })
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
pub struct RegistryProtocol {
    pub version: String,
    pub resources: Vec<String>,
    pub projections: Vec<String>,
}

impl Default for RegistryProtocol {
    fn default() -> Self {
        Self {
            version: "2026-06-24.alpha".to_string(),
            resources: [
                "repositories",
                "galaxies",
                "blobs",
                "snapshots",
                "refs",
                "workspaces",
                "changesets",
                "proposals",
                "merge-intents",
                "environments",
                "environment-variables",
                "policies",
                "vector-indexes",
                "vector-search",
                "vector-explain",
                "projections",
                "build-projections",
                "git-exports",
                "deploy-intents",
                "auth-tokens",
                "proposal-comments",
                "proposal-checks",
                "webhook-endpoints",
                "webhook-events",
                "sync-sessions",
                "vector-index-jobs",
            ]
            .into_iter()
            .map(String::from)
            .collect(),
            projections: ["github", "git-remote", "vercel", "ci", "local"]
                .into_iter()
                .map(String::from)
                .collect(),
        }
    }
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
pub struct RepositoryRecord {
    pub id: RepositoryId,
    pub name: String,
    #[serde(default)]
    pub org_id: Option<String>,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
pub struct CreateRepositoryRequest {
    pub name: String,
    #[serde(default)]
    pub org_id: Option<String>,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
pub struct BlobPutRequest {
    pub bytes_utf8: String,
    pub media_type: Option<String>,
    pub visibility: BlobVisibility,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
pub struct BlobPutResponse {
    pub blob: ContentBlob,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
pub struct RegistryBlobRecord {
    pub blob: ContentBlob,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
pub struct RegistrySyncBundle {
    pub repository_id: RepositoryId,
    pub default_ref: String,
    pub refs: Vec<Ref>,
    pub snapshots: Vec<TreeSnapshot>,
    pub changesets: Vec<ChangeSet>,
    pub proposals: Vec<Proposal>,
    pub operations: Vec<Operation>,
    #[serde(default)]
    pub git_migration_records: Vec<GitMigrationRecord>,
    #[serde(default)]
    pub environment_variables: Vec<EnvironmentVariable>,
    #[serde(default)]
    pub environment_variable_versions: Vec<EnvironmentVariableVersion>,
    #[serde(default)]
    pub environments: Vec<Environment>,
    pub blobs: Vec<RegistryBlobRecord>,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
pub struct EnvironmentVariableView {
    pub variable: EnvironmentVariable,
    #[serde(default)]
    pub current_version: Option<EnvironmentVariableVersionView>,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
pub struct EnvironmentVariableVersionView {
    pub id: EnvironmentVariableVersionId,
    pub variable_id: EnvironmentVariableId,
    pub key: String,
    pub sensitivity: VariableSensitivity,
    pub value_kind: VariableValueKind,
    pub storage_mode: VariableSecretStorageMode,
    #[serde(default)]
    pub masked_value: Option<String>,
    #[serde(default)]
    pub plaintext_value: Option<String>,
    #[serde(default)]
    pub content_hash: Option<ContentHash>,
    #[serde(default)]
    pub encryption_key_id: Option<String>,
    #[serde(default)]
    pub wrapped_data_key: Option<String>,
    #[serde(default)]
    pub nonce: Option<String>,
    #[serde(default)]
    pub fingerprint: Option<String>,
    #[serde(default)]
    pub value_digest: Option<String>,
    pub created_at_unix_ms: u64,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
pub struct ListEnvironmentVariablesResponse {
    pub variables: Vec<EnvironmentVariableView>,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
pub struct UpsertEnvironmentVariableRequest {
    pub key: String,
    #[serde(default)]
    pub workspace_id: Option<WorkspaceId>,
    #[serde(default)]
    pub scope: Option<VariableScope>,
    #[serde(default)]
    pub value_kind: Option<VariableValueKind>,
    #[serde(default)]
    pub availability: Vec<VariableAvailability>,
    #[serde(default)]
    pub sensitivity: Option<VariableSensitivity>,
    #[serde(default)]
    pub storage_mode: Option<VariableSecretStorageMode>,
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default)]
    pub reference: Option<VariableReference>,
    #[serde(default)]
    pub actor: Option<Actor>,
    #[serde(default)]
    pub stage: bool,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
pub struct UpsertEnvironmentVariableResponse {
    pub variable: EnvironmentVariableView,
    #[serde(default)]
    pub change: Option<EnvironmentVariableChange>,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
pub struct InjectEnvironmentVariablesRequest {
    #[serde(default)]
    pub workspace_id: Option<WorkspaceId>,
    #[serde(default)]
    pub service_id: Option<String>,
    #[serde(default)]
    pub availability: Option<VariableAvailability>,
    pub actor: Actor,
    #[serde(default)]
    pub deploy_intent_id: Option<DeployIntentId>,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
pub struct InjectedEnvironmentVariable {
    pub key: String,
    pub value: String,
    pub variable_id: EnvironmentVariableId,
    pub version_id: EnvironmentVariableVersionId,
    pub sensitivity: VariableSensitivity,
    pub availability: Vec<VariableAvailability>,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
pub struct InjectEnvironmentVariablesResponse {
    pub variables: Vec<InjectedEnvironmentVariable>,
    #[serde(default)]
    pub redaction_tokens: BTreeMap<String, Vec<String>>,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
pub struct SyncChunkUploadRequest {
    pub chunk: BlobChunk,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
pub struct SyncChunkRecord {
    pub repository_id: RepositoryId,
    pub session_id: SyncSessionId,
    pub chunk: BlobChunk,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
pub struct SyncSessionValidation {
    pub session_id: SyncSessionId,
    pub valid: bool,
    pub missing_chunks: Vec<BlobChunkId>,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
pub struct BlobPresenceRequest {
    pub blobs: Vec<ContentBlob>,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
pub struct BlobPresenceResponse {
    pub present: Vec<ContentHash>,
    pub missing: Vec<ContentBlob>,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
pub struct BlobUploadBatchRequest {
    pub blobs: Vec<ContentBlob>,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
pub struct BlobUploadBatchResponse {
    pub present: Vec<ContentHash>,
    pub uploads: Vec<BlobUploadAction>,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
pub struct BlobUploadAction {
    pub blob: ContentBlob,
    pub transfer: BlobUploadTransfer,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BlobUploadTransfer {
    DirectPut {
        url: String,
        headers: BTreeMap<String, String>,
        expires_at_unix_ms: u64,
    },
    RegistryPut,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
pub struct BlobUploadConfirmRequest {
    pub blobs: Vec<ContentBlob>,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
pub struct BlobUploadConfirmResponse {
    pub uploaded: Vec<ContentHash>,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
pub struct BlobPackEntry {
    pub blob: ContentBlob,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
pub struct BlobPackUploadRequest {
    pub blobs: Vec<BlobPackEntry>,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
pub struct BlobPackUploadResponse {
    pub uploaded: Vec<ContentHash>,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
pub enum SyncDirection {
    Push,
    Pull,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
pub struct StartSyncSessionRequest {
    pub direction: SyncDirection,
    pub base_ref: Option<String>,
    pub lease_token: String,
    pub actor: Actor,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
pub struct BlobBatchRequest {
    pub hashes: Vec<ContentHash>,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
pub struct BlobBatchResponse {
    pub blobs: Vec<ContentBlob>,
    pub missing: Vec<ContentHash>,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
pub struct BlobChunksResponse {
    pub blob: ContentBlob,
    pub chunks: Vec<BlobChunk>,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
pub struct TreeQuery {
    pub path: Option<String>,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
pub struct TreeResponse {
    pub node: TreeNode,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
pub struct TreeBatchRequest {
    pub snapshot_id: TreeSnapshotId,
    pub paths: Vec<String>,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
pub struct TreeBatchResponse {
    pub nodes: Vec<TreeNode>,
    pub missing: Vec<String>,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
pub struct CreateWorkspaceRequest {
    pub repository_id: RepositoryId,
    pub base_snapshot_id: TreeSnapshotId,
    pub owner: WorkspaceOwner,
    pub environment_id: Option<EnvironmentId>,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
pub struct CreateProposalRequest {
    pub repository_id: RepositoryId,
    pub title: String,
    pub target_ref_id: RefId,
    pub changeset_ids: Vec<ChangeSetId>,
    pub actor: Actor,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
pub struct ResolveRefResponse {
    pub reference: Ref,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
pub struct CreateWorkspaceResponse {
    pub workspace: AgentWorkspace,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
pub struct CreateProposalResponse {
    pub proposal: Proposal,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
pub struct BuildProjectionRequest {
    pub snapshot_id: TreeSnapshotId,
    pub environment: Environment,
    pub actor: Actor,
    pub target: ProjectionTarget,
    pub path_scope: Option<String>,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
pub struct BuildProjectionResponse {
    pub projection: Projection,
    pub manifest: ProjectionManifest,
    pub actions: Vec<BuildProjectionAction>,
    pub blocked: bool,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
pub struct BuildProjectionAction {
    pub path: String,
    pub decision: PolicyDecision,
    pub reason: String,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
pub struct CreateDeployIntentRequest {
    pub projection_id: ProjectionId,
    pub environment_id: EnvironmentId,
    pub requested_provider_key: String,
    pub requested_by: Actor,
    pub target: Option<DeployTarget>,
    pub release_gate_id: Option<ReleaseGateId>,
    pub trigger_source: Option<DeployTriggerSource>,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
pub struct CreateAuthTokenRequest {
    pub name: String,
    pub actor: Actor,
    pub kind: AuthTokenKind,
    pub scopes: Vec<PolicyAction>,
    #[serde(default)]
    pub org_id: Option<String>,
    #[serde(default)]
    pub expires_at_unix_ms: Option<u64>,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
pub struct CreateAuthTokenResponse {
    pub token: AuthToken,
    pub raw_token: String,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
pub struct StoredCedarPolicyDocument {
    pub id: String,
    pub repository_id: RepositoryId,
    pub text: String,
    pub version: u64,
    pub enabled: bool,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
pub struct DeployIntentResponse {
    pub intent: DeployIntent,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
pub struct DeployStatusCallbackRequest {
    pub state: DeployIntentState,
    pub artifacts: Vec<DeployArtifactRef>,
    pub log_uri: Option<String>,
    pub error_message: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct DeployArchiveQuery {
    pub expires_unix_ms: u64,
    pub signature: String,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
pub struct VectorIndexRequest {
    pub snapshot_id: Option<TreeSnapshotId>,
    pub projection_id: Option<ProjectionId>,
    pub actor: Actor,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
pub struct VectorIndexResponse {
    pub manifest: VectorIndexManifest,
    pub job: VectorIndexJob,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
pub struct VectorSearchRequest {
    pub manifest_id: Option<VectorIndexManifestId>,
    pub snapshot_id: Option<TreeSnapshotId>,
    pub query: String,
    pub top_k: Option<usize>,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
pub struct VectorSearchHit {
    pub path: String,
    pub start_line: Option<u32>,
    pub end_line: Option<u32>,
    pub score: f32,
    pub snippet: String,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
pub struct VectorSearchResponse {
    pub manifest_id: VectorIndexManifestId,
    pub hits: Vec<VectorSearchHit>,
}

const OCI_METADATA_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
pub struct OciBlob {
    pub schema_version: u32,
    pub repository_name: String,
    pub repository_name_normalized: String,
    pub digest: String,
    pub size_bytes: u64,
    pub media_type: Option<String>,
    pub storage_key: String,
    pub created_at_unix_ms: u64,
    pub updated_at_unix_ms: u64,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
pub struct OciManifest {
    pub schema_version: u32,
    pub repository_name: String,
    pub repository_name_normalized: String,
    pub reference: Option<String>,
    pub digest: String,
    pub media_type: String,
    pub size_bytes: u64,
    pub bytes: Vec<u8>,
    pub referenced_digests: Vec<String>,
    pub created_at_unix_ms: u64,
    pub updated_at_unix_ms: u64,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
pub struct OciTag {
    pub schema_version: u32,
    pub repository_name: String,
    pub repository_name_normalized: String,
    pub tag: String,
    pub manifest_digest: String,
    pub actor: Option<Actor>,
    pub created_at_unix_ms: u64,
    pub updated_at_unix_ms: u64,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
pub struct OciUploadSession {
    pub schema_version: u32,
    pub uuid: String,
    pub repository_name: String,
    pub repository_name_normalized: String,
    pub partial_object_path: String,
    pub received_bytes: u64,
    pub bytes: Vec<u8>,
    pub created_at_unix_ms: u64,
    pub updated_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
pub struct OciProvenance {
    pub schema_version: u32,
    pub manifest_digest: String,
    pub repository_name: String,
    pub repository_name_normalized: String,
    pub nebula_repository_id: Option<RepositoryId>,
    pub snapshot_id: Option<TreeSnapshotId>,
    pub projection_id: Option<ProjectionId>,
    pub deploy_intent_id: Option<DeployIntentId>,
    pub actor: Option<Actor>,
    pub policy_digest: Option<String>,
    pub build_id: Option<String>,
    pub created_at_unix_ms: u64,
    pub updated_at_unix_ms: u64,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
pub struct VectorExplainRequest {
    pub manifest_id: VectorIndexManifestId,
    pub path: String,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
pub struct VectorExplainResponse {
    pub manifest_id: VectorIndexManifestId,
    pub path: String,
    pub chunk: Option<CodeEmbeddingChunk>,
}

#[derive(Clone, Default)]
pub struct InMemoryRegistry {
    repositories: BTreeMap<RepositoryId, RepositoryRecord>,
    blobs: BTreeMap<ContentHash, (ContentBlob, Vec<u8>)>,
    oci_blobs: BTreeMap<String, (OciBlob, Vec<u8>)>,
    oci_manifests: BTreeMap<(String, String), OciManifest>,
    oci_tags: BTreeMap<(String, String), OciTag>,
    oci_upload_sessions: BTreeMap<String, OciUploadSession>,
    oci_provenance: BTreeMap<String, OciProvenance>,
    snapshots: BTreeMap<TreeSnapshotId, TreeSnapshot>,
    refs: BTreeMap<(RepositoryId, String), Ref>,
    workspaces: BTreeMap<WorkspaceId, AgentWorkspace>,
    changesets: BTreeMap<ChangeSetId, ChangeSet>,
    proposals: BTreeMap<ProposalId, Proposal>,
    merge_intents: BTreeMap<MergeIntentId, MergeIntent>,
    release_gates: BTreeMap<ReleaseGateId, ReleaseGate>,
    environments: BTreeMap<EnvironmentId, Environment>,
    environment_variables: BTreeMap<EnvironmentVariableId, EnvironmentVariable>,
    environment_variable_versions:
        BTreeMap<EnvironmentVariableVersionId, EnvironmentVariableVersion>,
    environment_variable_changes: BTreeMap<String, EnvironmentVariableChange>,
    integrations: BTreeMap<String, IntegrationActor>,
    policies: BTreeMap<PolicyId, VisibilityPolicy>,
    cedar_policy_documents: BTreeMap<String, StoredCedarPolicyDocument>,
    vector_manifests: BTreeMap<VectorIndexManifestId, VectorIndexManifest>,
    projections: BTreeMap<ProjectionId, Projection>,
    git_exports: BTreeMap<GitExportId, GitExport>,
    git_migration_records: BTreeMap<GitMigrationRecordId, GitMigrationRecord>,
    operations: BTreeMap<OperationId, Operation>,
    deploy_intents: BTreeMap<DeployIntentId, DeployIntent>,
    deployment_grants: BTreeMap<DeploymentGrantId, DeploymentGrant>,
    auth_tokens: BTreeMap<AuthTokenId, AuthToken>,
    proposal_comments: BTreeMap<ReviewCommentId, ProposalComment>,
    proposal_checks: BTreeMap<StatusCheckId, ProposalStatusCheck>,
    deploy_configs: BTreeMap<(RepositoryId, String), RepositoryDeployConfig>,
    webhook_endpoints: BTreeMap<WebhookEndpointId, WebhookEndpoint>,
    webhook_events: BTreeMap<WebhookEventId, WebhookEvent>,
    sync_sessions: BTreeMap<SyncSessionId, SyncSession>,
    chunk_manifests: BTreeMap<SyncSessionId, ChunkTransferManifest>,
    sync_chunks: BTreeMap<(SyncSessionId, BlobChunkId), SyncChunkRecord>,
    staged_blob_uploads: BTreeMap<(SyncSessionId, BlobId), StagedBlobUpload>,
    sync_bundles: BTreeMap<SyncSessionId, RegistrySyncBundle>,
    authorization_audits: Vec<Value>,
    vector_index_jobs: BTreeMap<VectorIndexJobId, VectorIndexJob>,
}

#[derive(Clone, Debug, Default, JsonSchema, Serialize, Deserialize)]
pub struct PersistedRegistry {
    pub repositories: Vec<RepositoryRecord>,
    pub blobs: Vec<PersistedBlob>,
    #[serde(default)]
    pub oci_blobs: Vec<PersistedOciBlob>,
    #[serde(default)]
    pub oci_manifests: Vec<OciManifest>,
    #[serde(default)]
    pub oci_tags: Vec<OciTag>,
    #[serde(default)]
    pub oci_upload_sessions: Vec<OciUploadSession>,
    #[serde(default)]
    pub oci_provenance: Vec<OciProvenance>,
    pub snapshots: Vec<TreeSnapshot>,
    pub refs: Vec<Ref>,
    pub workspaces: Vec<AgentWorkspace>,
    pub changesets: Vec<ChangeSet>,
    pub proposals: Vec<Proposal>,
    pub merge_intents: Vec<MergeIntent>,
    pub release_gates: Vec<ReleaseGate>,
    pub environments: Vec<Environment>,
    #[serde(default)]
    pub environment_variables: Vec<EnvironmentVariable>,
    #[serde(default)]
    pub environment_variable_versions: Vec<EnvironmentVariableVersion>,
    #[serde(default)]
    pub environment_variable_changes: Vec<EnvironmentVariableChange>,
    pub integrations: Vec<IntegrationActor>,
    pub policies: Vec<VisibilityPolicy>,
    #[serde(default)]
    pub cedar_policy_documents: Vec<StoredCedarPolicyDocument>,
    pub vector_manifests: Vec<VectorIndexManifest>,
    pub projections: Vec<Projection>,
    pub git_exports: Vec<GitExport>,
    #[serde(default)]
    pub git_migration_records: Vec<GitMigrationRecord>,
    pub operations: Vec<Operation>,
    #[serde(default)]
    pub deploy_intents: Vec<DeployIntent>,
    pub deployment_grants: Vec<DeploymentGrant>,
    #[serde(default)]
    pub deploy_configs: Vec<RepositoryDeployConfig>,
    #[serde(default)]
    pub auth_tokens: Vec<AuthToken>,
    #[serde(default)]
    pub proposal_comments: Vec<ProposalComment>,
    #[serde(default)]
    pub proposal_checks: Vec<ProposalStatusCheck>,
    #[serde(default)]
    pub webhook_endpoints: Vec<WebhookEndpoint>,
    #[serde(default)]
    pub webhook_events: Vec<WebhookEvent>,
    #[serde(default)]
    pub sync_sessions: Vec<SyncSession>,
    #[serde(default)]
    pub chunk_manifests: Vec<ChunkTransferManifest>,
    #[serde(default)]
    pub sync_chunks: Vec<SyncChunkRecord>,
    #[serde(default)]
    pub sync_bundles: Vec<(SyncSessionId, RegistrySyncBundle)>,
    #[serde(default)]
    pub authorization_audits: Vec<Value>,
    #[serde(default)]
    pub vector_index_jobs: Vec<VectorIndexJob>,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
pub struct PersistedBlob {
    pub blob: ContentBlob,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
pub struct PersistedOciBlob {
    pub blob: OciBlob,
    pub bytes: Vec<u8>,
}

impl InMemoryRegistry {
    pub fn load_from_path(path: &PathBuf) -> std::io::Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let content = fs::read_to_string(path)?;
        let persisted: PersistedRegistry = serde_json::from_str(&content)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
        Ok(Self::from(persisted))
    }

    pub fn save_to_path(&self, path: &PathBuf) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let persisted = PersistedRegistry::from(self.clone());
        let content = serde_json::to_string_pretty(&persisted).map_err(std::io::Error::other)?;
        atomic_write_file(path, format!("{content}\n").as_bytes())
    }
}

/// Load a file-backed registry snapshot.
///
/// Missing files bootstrap an empty registry. Corrupt or unreadable files fail
/// closed so the process cannot silently start with an empty writable index.
fn load_registry_from_persistence(path: Option<&PathBuf>) -> Result<InMemoryRegistry, String> {
    let Some(path) = path else {
        return Ok(InMemoryRegistry::default());
    };
    match InMemoryRegistry::load_from_path(path) {
        Ok(registry) => Ok(registry),
        Err(error) => {
            tracing::error!(
                path = %path.display(),
                error = %error,
                "failed to load registry persistence; refusing empty boot"
            );
            Err(format!(
                "failed to load registry persistence at {}: {error}",
                path.display()
            ))
        }
    }
}

fn atomic_write_file(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    fs::create_dir_all(parent)?;
    let temp_path = path.with_file_name(format!(
        ".nebula-registry-tmp-{}-{}",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("registry.json"),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default()
    ));
    {
        let mut file = fs::File::create(&temp_path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    fs::rename(&temp_path, path)?;
    if let Ok(dir) = fs::File::open(parent) {
        let _ = dir.sync_all();
    }
    Ok(())
}

impl From<PersistedRegistry> for InMemoryRegistry {
    fn from(value: PersistedRegistry) -> Self {
        Self {
            repositories: value
                .repositories
                .into_iter()
                .map(|repo| (repo.id.clone(), repo))
                .collect(),
            blobs: value
                .blobs
                .into_iter()
                .map(|persisted| {
                    (
                        persisted.blob.hash.clone(),
                        (persisted.blob, persisted.bytes),
                    )
                })
                .collect(),
            oci_blobs: value
                .oci_blobs
                .into_iter()
                .map(|persisted| {
                    (
                        persisted.blob.digest.clone(),
                        (persisted.blob, persisted.bytes),
                    )
                })
                .collect(),
            oci_manifests: value
                .oci_manifests
                .into_iter()
                .map(|manifest| {
                    (
                        (
                            manifest.repository_name_normalized.clone(),
                            manifest.digest.clone(),
                        ),
                        manifest,
                    )
                })
                .collect(),
            oci_tags: value
                .oci_tags
                .into_iter()
                .map(|tag| {
                    (
                        (tag.repository_name_normalized.clone(), tag.tag.clone()),
                        tag,
                    )
                })
                .collect(),
            oci_upload_sessions: value
                .oci_upload_sessions
                .into_iter()
                .map(|session| (session.uuid.clone(), session))
                .collect(),
            oci_provenance: value
                .oci_provenance
                .into_iter()
                .map(|provenance| (provenance.manifest_digest.clone(), provenance))
                .collect(),
            snapshots: value
                .snapshots
                .into_iter()
                .map(|snapshot| (snapshot.id.clone(), snapshot))
                .collect(),
            refs: value
                .refs
                .into_iter()
                .map(|reference| {
                    (
                        (reference.repository_id.clone(), reference.name.clone()),
                        reference,
                    )
                })
                .collect(),
            workspaces: value
                .workspaces
                .into_iter()
                .map(|workspace| (workspace.id.clone(), workspace))
                .collect(),
            changesets: value
                .changesets
                .into_iter()
                .map(|changeset| (changeset.id.clone(), changeset))
                .collect(),
            proposals: value
                .proposals
                .into_iter()
                .map(|proposal| (proposal.id.clone(), proposal))
                .collect(),
            merge_intents: value
                .merge_intents
                .into_iter()
                .map(|intent| (intent.id.clone(), intent))
                .collect(),
            release_gates: value
                .release_gates
                .into_iter()
                .map(|gate| (gate.id.clone(), gate))
                .collect(),
            environments: value
                .environments
                .into_iter()
                .map(|environment| (environment.id.clone(), environment))
                .collect(),
            environment_variables: value
                .environment_variables
                .into_iter()
                .map(|variable| (variable.id.clone(), variable))
                .collect(),
            environment_variable_versions: value
                .environment_variable_versions
                .into_iter()
                .map(|version| (version.id.clone(), version))
                .collect(),
            environment_variable_changes: value
                .environment_variable_changes
                .into_iter()
                .map(|change| (change.id.clone(), change))
                .collect(),
            integrations: value
                .integrations
                .into_iter()
                .map(|integration| (integration.provider.clone(), integration))
                .collect(),
            policies: value
                .policies
                .into_iter()
                .map(|policy| (policy.id.clone(), policy))
                .collect(),
            cedar_policy_documents: value
                .cedar_policy_documents
                .into_iter()
                .map(|document| (document.id.clone(), document))
                .collect(),
            vector_manifests: value
                .vector_manifests
                .into_iter()
                .map(|manifest| (manifest.id.clone(), manifest))
                .collect(),
            projections: value
                .projections
                .into_iter()
                .map(|projection| (projection.id.clone(), projection))
                .collect(),
            git_exports: value
                .git_exports
                .into_iter()
                .map(|export| (export.id.clone(), export))
                .collect(),
            git_migration_records: value
                .git_migration_records
                .into_iter()
                .map(|record| (record.id.clone(), record))
                .collect(),
            operations: value
                .operations
                .into_iter()
                .map(|operation| (operation.id.clone(), operation))
                .collect(),
            deploy_intents: value
                .deploy_intents
                .into_iter()
                .map(|intent| (intent.id.clone(), intent))
                .collect(),
            deployment_grants: value
                .deployment_grants
                .into_iter()
                .map(|grant| (grant.id.clone(), grant))
                .collect(),
            deploy_configs: value
                .deploy_configs
                .into_iter()
                .map(|config| {
                    (
                        (config.repository_id.clone(), config.service_id.clone()),
                        config,
                    )
                })
                .collect(),
            auth_tokens: value
                .auth_tokens
                .into_iter()
                .map(|token| (token.id.clone(), token))
                .collect(),
            proposal_comments: value
                .proposal_comments
                .into_iter()
                .map(|comment| (comment.id.clone(), comment))
                .collect(),
            proposal_checks: value
                .proposal_checks
                .into_iter()
                .map(|check| (check.id.clone(), check))
                .collect(),
            webhook_endpoints: value
                .webhook_endpoints
                .into_iter()
                .map(|endpoint| (endpoint.id.clone(), endpoint))
                .collect(),
            webhook_events: value
                .webhook_events
                .into_iter()
                .map(|event| (event.id.clone(), event))
                .collect(),
            sync_sessions: value
                .sync_sessions
                .into_iter()
                .map(|session| (session.id.clone(), session))
                .collect(),
            chunk_manifests: value
                .chunk_manifests
                .into_iter()
                .map(|manifest| (manifest.session_id.clone(), manifest))
                .collect(),
            sync_chunks: value
                .sync_chunks
                .into_iter()
                .map(|record| ((record.session_id.clone(), record.chunk.id.clone()), record))
                .collect(),
            staged_blob_uploads: BTreeMap::new(),
            sync_bundles: value.sync_bundles.into_iter().collect(),
            authorization_audits: value.authorization_audits,
            vector_index_jobs: value
                .vector_index_jobs
                .into_iter()
                .map(|job| (job.id.clone(), job))
                .collect(),
        }
    }
}

impl From<InMemoryRegistry> for PersistedRegistry {
    fn from(value: InMemoryRegistry) -> Self {
        Self {
            repositories: value.repositories.into_values().collect(),
            blobs: value
                .blobs
                .into_values()
                .map(|(blob, bytes)| PersistedBlob { blob, bytes })
                .collect(),
            oci_blobs: value
                .oci_blobs
                .into_values()
                .map(|(blob, bytes)| PersistedOciBlob { blob, bytes })
                .collect(),
            oci_manifests: value.oci_manifests.into_values().collect(),
            oci_tags: value.oci_tags.into_values().collect(),
            oci_upload_sessions: value.oci_upload_sessions.into_values().collect(),
            oci_provenance: value.oci_provenance.into_values().collect(),
            snapshots: value.snapshots.into_values().collect(),
            refs: value.refs.into_values().collect(),
            workspaces: value.workspaces.into_values().collect(),
            changesets: value.changesets.into_values().collect(),
            proposals: value.proposals.into_values().collect(),
            merge_intents: value.merge_intents.into_values().collect(),
            release_gates: value.release_gates.into_values().collect(),
            environments: value.environments.into_values().collect(),
            environment_variables: value.environment_variables.into_values().collect(),
            environment_variable_versions: value
                .environment_variable_versions
                .into_values()
                .collect(),
            environment_variable_changes: value
                .environment_variable_changes
                .into_values()
                .collect(),
            integrations: value.integrations.into_values().collect(),
            policies: value.policies.into_values().collect(),
            cedar_policy_documents: value.cedar_policy_documents.into_values().collect(),
            vector_manifests: value.vector_manifests.into_values().collect(),
            projections: value.projections.into_values().collect(),
            git_exports: value.git_exports.into_values().collect(),
            git_migration_records: value.git_migration_records.into_values().collect(),
            operations: value.operations.into_values().collect(),
            deploy_intents: value.deploy_intents.into_values().collect(),
            deployment_grants: value.deployment_grants.into_values().collect(),
            deploy_configs: value.deploy_configs.into_values().collect(),
            auth_tokens: value.auth_tokens.into_values().collect(),
            proposal_comments: value.proposal_comments.into_values().collect(),
            proposal_checks: value.proposal_checks.into_values().collect(),
            webhook_endpoints: value.webhook_endpoints.into_values().collect(),
            webhook_events: value.webhook_events.into_values().collect(),
            sync_sessions: value.sync_sessions.into_values().collect(),
            chunk_manifests: value.chunk_manifests.into_values().collect(),
            sync_chunks: value.sync_chunks.into_values().collect(),
            sync_bundles: value.sync_bundles.into_iter().collect(),
            authorization_audits: value.authorization_audits,
            vector_index_jobs: value.vector_index_jobs.into_values().collect(),
        }
    }
}

fn apply_bootstrap_auth_tokens(
    registry: &mut InMemoryRegistry,
    tokens: &[RegistryBootstrapAuthToken],
) {
    for token in tokens {
        let raw_token = token.raw_token.trim();
        if raw_token.is_empty() || token.scopes.is_empty() {
            continue;
        }
        let token_id = AuthTokenId::new(format!(
            "tok_bootstrap_{}",
            &ContentHash::sha256(raw_token.as_bytes()).digest[..16]
        ));
        let auth_token = AuthToken {
            id: token_id.clone(),
            repository_id: None,
            org_id: None,
            actor: Actor::Integration(token.name.clone()),
            kind: AuthTokenKind::Integration,
            name: token.name.clone(),
            token_hash: ContentHash::sha256(raw_token.as_bytes()).digest,
            scopes: token.scopes.clone(),
            expires_at_unix_ms: None,
            revoked_at_unix_ms: None,
        };
        registry.auth_tokens.insert(token_id, auth_token);
    }
}

#[derive(Clone)]
struct AppState {
    registry: Arc<RwLock<InMemoryRegistry>>,
    persistence_path: Option<PathBuf>,
    auth: AuthConfig,
    external_auth_provider: Option<Arc<dyn RegistryAuthProvider>>,
    external_auth_cache: Arc<RwLock<BTreeMap<String, ExternalAuthCacheEntry>>>,
    durable_store: Option<Arc<dyn RegistryStore>>,
    blob_store: Option<Arc<dyn BlobStore>>,
    object_blob_store: Option<Arc<ObjectBlobStore>>,
    vector_store: Option<Arc<dyn VectorIndexStore>>,
    public_base_url: Option<String>,
    astracollab_deploy_url: Option<String>,
    astracollab_deploy_signing_secret: Option<String>,
    deploy_archive_cache: Arc<RwLock<BTreeMap<String, Arc<Vec<u8>>>>>,
    telemetry_sinks: Vec<String>,
    telemetry_event_file: Option<PathBuf>,
    telemetry_webhook_url: Option<String>,
    telemetry_webhook_secret: Option<String>,
    secret_encryption_key: Option<String>,
    http_client: reqwest::Client,
}

#[derive(Clone)]
struct ExternalAuthCacheEntry {
    claims: VerifiedClaims,
    expires_at_unix_ms: u64,
}

fn external_auth_cache_key(token: &str, repository_id: Option<&RepositoryId>) -> String {
    let repository_id = repository_id
        .map(|id| id.as_str())
        .unwrap_or("<no-repository>");
    format!(
        "{}:{}",
        repository_id,
        ContentHash::sha256(token.as_bytes()).digest
    )
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: message.into(),
        }
    }

    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        let message = message.into();
        tracing::error!(%message, "internal api error");
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: "internal server error".to_string(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({ "error": self.message }))).into_response()
    }
}

fn emit_telemetry_event(state: AppState, event: NebulaTelemetryEvent) {
    if state.telemetry_sinks.iter().any(|sink| sink == "json") {
        tracing::info!(
            event_id = %event.event_id,
            event_type = %event.event_type,
            source = ?event.source,
            severity = ?event.severity,
            repository_id = ?event.context.repository_id,
            sync_session_id = ?event.context.sync_session_id,
            "nebula telemetry event: {}",
            event.message
        );
    }
    if state.telemetry_event_file.is_none() && state.telemetry_webhook_url.is_none() {
        return;
    }
    tokio::spawn(async move {
        if let Some(path) = &state.telemetry_event_file
            && let Err(error) = append_telemetry_event(path, &event).await
        {
            tracing::warn!(%error, event_id = %event.event_id, "failed to append telemetry event");
        }
        if let Some(url) = &state.telemetry_webhook_url
            && let Err(error) = post_telemetry_event(&state, url, &event).await
        {
            tracing::warn!(%error, event_id = %event.event_id, "failed to post telemetry event");
        }
    });
}

async fn append_telemetry_event(
    path: &PathBuf,
    event: &NebulaTelemetryEvent,
) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|error| error.to_string())?;
    }
    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await
        .map_err(|error| error.to_string())?;
    let line = serde_json::to_string(event).map_err(|error| error.to_string())?;
    file.write_all(line.as_bytes())
        .await
        .map_err(|error| error.to_string())?;
    file.write_all(b"\n")
        .await
        .map_err(|error| error.to_string())
}

async fn post_telemetry_event(
    state: &AppState,
    url: &str,
    event: &NebulaTelemetryEvent,
) -> Result<(), String> {
    let body = serde_json::to_string(event).map_err(|error| error.to_string())?;
    let mut request = state
        .http_client
        .post(url)
        .header("content-type", "application/json")
        .header("x-nebula-event-id", event.event_id.as_str())
        .header("x-nebula-sent-at", event.created_at_unix_ms.to_string());
    if let Some(secret) = &state.telemetry_webhook_secret {
        let digest = sha256_hex(&format!(
            "{}:{}:{}:{}",
            secret, event.event_id, event.created_at_unix_ms, body
        ));
        request = request.header("x-nebula-signature", format!("sha256:{digest}"));
    }
    request
        .body(body)
        .send()
        .await
        .map_err(|error| error.to_string())?
        .error_for_status()
        .map_err(|error| error.to_string())?;
    Ok(())
}

fn telemetry_event(
    event_type: impl Into<String>,
    source: TelemetrySource,
    severity: TelemetrySeverity,
    message: impl Into<String>,
    context: NebulaTelemetryContext,
    attributes: BTreeMap<String, Value>,
) -> NebulaTelemetryEvent {
    let created_at_unix_ms = now_unix_ms();
    let event_type = event_type.into();
    NebulaTelemetryEvent {
        event_id: format!(
            "evt-{}-{}",
            created_at_unix_ms,
            &sha256_hex(&format!("{event_type}:{created_at_unix_ms}"))[..12]
        ),
        event_type,
        source,
        severity,
        message: message.into(),
        context,
        created_at_unix_ms,
        attributes,
    }
}

fn sha256_hex(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    hex::encode(hasher.finalize())
}

async fn schema() -> Json<Value> {
    let mut schemas = serde_json::Map::new();
    macro_rules! insert_schema {
        ($name:literal, $ty:ty) => {
            schemas.insert($name.to_string(), json!(schema_for!($ty)));
        };
    }

    insert_schema!("CreateRepositoryRequest", CreateRepositoryRequest);
    insert_schema!("RepositoryRecord", RepositoryRecord);
    insert_schema!("BlobPutRequest", BlobPutRequest);
    insert_schema!("BlobPutResponse", BlobPutResponse);
    insert_schema!("RegistryBlobRecord", RegistryBlobRecord);
    insert_schema!("RegistrySyncBundle", RegistrySyncBundle);
    insert_schema!("BlobBatchRequest", BlobBatchRequest);
    insert_schema!("BlobBatchResponse", BlobBatchResponse);
    insert_schema!("BlobChunksResponse", BlobChunksResponse);
    insert_schema!("TreeQuery", TreeQuery);
    insert_schema!("TreeResponse", TreeResponse);
    insert_schema!("TreeBatchRequest", TreeBatchRequest);
    insert_schema!("TreeBatchResponse", TreeBatchResponse);
    insert_schema!("TreeSnapshot", TreeSnapshot);
    insert_schema!("Ref", Ref);
    insert_schema!("CreateWorkspaceRequest", CreateWorkspaceRequest);
    insert_schema!("CreateWorkspaceResponse", CreateWorkspaceResponse);
    insert_schema!("ChangeSet", ChangeSet);
    insert_schema!("CreateProposalRequest", CreateProposalRequest);
    insert_schema!("CreateProposalResponse", CreateProposalResponse);
    insert_schema!("BuildProjectionRequest", BuildProjectionRequest);
    insert_schema!("BuildProjectionResponse", BuildProjectionResponse);
    insert_schema!("BuildProjectionAction", BuildProjectionAction);
    insert_schema!("MergeIntent", MergeIntent);
    insert_schema!("MergeResult", nebula_core::MergeResult);
    insert_schema!("MergeConflict", MergeConflict);
    insert_schema!("ReleaseGate", ReleaseGate);
    insert_schema!("Environment", Environment);
    insert_schema!("IntegrationActor", IntegrationActor);
    insert_schema!("VisibilityPolicy", VisibilityPolicy);
    insert_schema!("StoredCedarPolicyDocument", StoredCedarPolicyDocument);
    insert_schema!("VectorIndexManifest", VectorIndexManifest);
    insert_schema!("Projection", Projection);
    insert_schema!("ProjectionManifest", ProjectionManifest);
    insert_schema!("GitExport", GitExport);
    insert_schema!("GitMigrationRecord", GitMigrationRecord);
    insert_schema!("Operation", Operation);
    insert_schema!("AffectedGraph", AffectedGraph);
    insert_schema!("DeployIntent", DeployIntent);
    insert_schema!("DeployIntentState", DeployIntentState);
    insert_schema!("DeployTarget", DeployTarget);
    insert_schema!("DeployPolicyEvidence", DeployPolicyEvidence);
    insert_schema!("ReleaseGateDecision", ReleaseGateDecision);
    insert_schema!("DeployReleaseGateEvidence", DeployReleaseGateEvidence);
    insert_schema!("AstracollabDeployHandoff", AstracollabDeployHandoff);
    insert_schema!("DeploymentGrant", DeploymentGrant);
    insert_schema!("WhoAmIResponse", WhoAmIResponse);
    insert_schema!("RepositoryDeployConfig", RepositoryDeployConfig);
    insert_schema!(
        "SetRepositoryDeployConfigRequest",
        SetRepositoryDeployConfigRequest
    );
    insert_schema!("AuthToken", AuthToken);
    insert_schema!("CreateAuthTokenRequest", CreateAuthTokenRequest);
    insert_schema!("CreateAuthTokenResponse", CreateAuthTokenResponse);
    insert_schema!("RegistryBootstrapAuthToken", RegistryBootstrapAuthToken);
    insert_schema!("ProposalComment", ProposalComment);
    insert_schema!("ProposalStatusCheck", ProposalStatusCheck);
    insert_schema!("WebhookEndpoint", WebhookEndpoint);
    insert_schema!("WebhookEvent", WebhookEvent);
    insert_schema!("SyncSession", SyncSession);
    insert_schema!("ChunkTransferManifest", ChunkTransferManifest);
    insert_schema!("SyncChunkUploadRequest", SyncChunkUploadRequest);
    insert_schema!("SyncChunkRecord", SyncChunkRecord);
    insert_schema!("BlobStreamDescriptor", BlobStreamDescriptor);
    insert_schema!("StagedBlobUpload", StagedBlobUpload);
    insert_schema!("OciBlob", OciBlob);
    insert_schema!("OciManifest", OciManifest);
    insert_schema!("OciTag", OciTag);
    insert_schema!("OciUploadSession", OciUploadSession);
    insert_schema!("OciProvenance", OciProvenance);
    insert_schema!("NebulaTelemetryEvent", NebulaTelemetryEvent);
    insert_schema!("NebulaOpsReportEnvelope", NebulaOpsReportEnvelope);
    insert_schema!("SyncSessionValidation", SyncSessionValidation);
    insert_schema!("BlobUploadBatchRequest", BlobUploadBatchRequest);
    insert_schema!("BlobUploadBatchResponse", BlobUploadBatchResponse);
    insert_schema!("BlobUploadAction", BlobUploadAction);
    insert_schema!("BlobUploadTransfer", BlobUploadTransfer);
    insert_schema!("BlobUploadConfirmRequest", BlobUploadConfirmRequest);
    insert_schema!("BlobUploadConfirmResponse", BlobUploadConfirmResponse);
    insert_schema!("StartSyncSessionRequest", StartSyncSessionRequest);
    insert_schema!("VectorIndexJob", VectorIndexJob);
    insert_schema!("PersistedRegistry", PersistedRegistry);

    Json(Value::Object(schemas))
}

async fn health_live(State(state): State<AppState>) -> Json<RegistryHealth> {
    Json(RegistryHealth {
        service: state.auth.token_authority.to_service_name(),
        status: "ok".to_string(),
    })
}

async fn health_ready(State(state): State<AppState>) -> Response {
    if state.registry.read().is_err() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "status": "unavailable", "error": "registry lock poisoned" })),
        )
            .into_response();
    }
    if state.durable_store.is_some() && state.blob_store.is_none() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "status": "unavailable", "error": "blob store is required with durable metadata" })),
        )
            .into_response();
    }
    Json(RegistryHealth {
        service: "nebula-registry".to_string(),
        status: "ready".to_string(),
    })
    .into_response()
}

impl AuthTokenAuthority {
    fn to_service_name(&self) -> String {
        match self {
            AuthTokenAuthority::AstracollabHosted => "nebula-registry-hosted".to_string(),
            AuthTokenAuthority::NebulaSelfHosted => "nebula-registry".to_string(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct ListGalaxiesQuery {
    #[serde(default)]
    org_id: Option<String>,
}

async fn list_galaxies(
    State(state): State<AppState>,
    claims: Option<Extension<VerifiedClaims>>,
    Query(params): Query<ListGalaxiesQuery>,
) -> Result<Json<Vec<RepositoryRecord>>, ApiError> {
    let (actor, bypasses_policy_checks) = claims
        .map(|Extension(claims)| {
            let bypass = claims.scopes.contains(&PolicyAction::ManageAuth);
            (claims.actor, bypass)
        })
        .unwrap_or((Actor::Public, false));
    let registry = state
        .registry
        .read()
        .map_err(|_| ApiError::internal("registry lock poisoned"))?;
    let policies = registry.policies.values().cloned().collect::<Vec<_>>();
    let mut accessible = Vec::new();
    for repo in registry.repositories.values() {
        if let Some(org_id) = &params.org_id
            && repo.org_id.as_deref() != Some(org_id.as_str())
        {
            continue;
        }
        // Mirrors the auth middleware's ManageAuth bypass (lib.rs auth_middleware):
        // an admin identity shouldn't need an explicit per-repo policy grant just
        // to see a galaxy in the list that `GET /v1/galaxies/{id}` already lets
        // them read directly.
        let authorized = bypasses_policy_checks || {
            let cedar_documents = registry
                .cedar_policy_documents
                .values()
                .filter(|document| document.enabled && document.repository_id == repo.id)
                .map(|document| nebula_policy::CedarPolicyDocument {
                    id: document.id.clone(),
                    repository_id: document.repository_id.clone(),
                    text: document.text.clone(),
                    version: document.version,
                    enabled: document.enabled,
                })
                .collect::<Vec<_>>();
            let authorizer =
                CedarNebulaAuthorizer::with_cedar_documents(policies.clone(), cedar_documents);
            authorizer
                .authorize(AuthorizationRequest {
                    actor: actor.clone(),
                    token_id: None,
                    action: PolicyAction::ReadBlob,
                    repository_id: repo.id.clone(),
                    resource_kind: "Repository".to_string(),
                    resource_id: format!("/v1/galaxies/{}", repo.id),
                    path: None,
                    environment: None,
                })
                .is_ok()
        };
        if authorized {
            accessible.push(repo.clone());
        }
    }
    Ok(Json(accessible))
}

/// Name of the `Actor::Integration` used by the astracollab dashboard's
/// server-side Nebula Registry client (bootstrap token configured via
/// `NEBULA_REGISTRY_ASTRACOLLAB_SERVICE_TOKEN`). Every galaxy is granted a
/// least-privilege policy trusting this actor for content sync (blob/tree
/// read+write) at creation time, since astracollab is itself the hosting
/// platform for the galaxy — see `default_astracollab_service_policy`.
const ASTRACOLLAB_SERVICE_ACTOR_NAME: &str = "astracollab-dashboard";
const HORIZON_INTEGRATION_ACTOR_NAME: &str = "horizon";

fn default_astracollab_service_policy(repository_id: &RepositoryId) -> VisibilityPolicy {
    VisibilityPolicy {
        id: PolicyId::generated(),
        repository_id: repository_id.clone(),
        name: "astracollab-dashboard-content-sync".to_string(),
        priority: 0,
        rules: vec![PolicyRule {
            actor: Actor::Integration(ASTRACOLLAB_SERVICE_ACTOR_NAME.to_string()),
            token_id: None,
            environment_id: None,
            environment_kind: None,
            path_glob: None,
            key_glob: None,
            service_id: None,
            workspace_id: None,
            sensitivity: None,
            availability: None,
            actions: vec![PolicyAction::ReadBlob, PolicyAction::WriteChangeSet],
            decision: PolicyDecision::Allow,
            reason: Some(
                "astracollab-dashboard service token: content sync for hosted galaxy".to_string(),
            ),
        }],
    }
}

/// Every galaxy created with an `org_id` automatically trusts a JWT-
/// authenticated `Actor::Team(org_id)` for baseline content sync. This is
/// what lets an external identity provider embedding Nebula (e.g. a SaaS
/// product minting its own per-org JWTs via JWKS, verified through
/// `AuthMode::Jwks`) allow members of that org to read/write their own
/// galaxy without any further registry-side policy configuration — there is
/// no policy-management API, so this default is the only way such a token
/// is ever authorized. Scoped to the galaxy's own `org_id` at creation time,
/// so a token minted for one org can never be replayed against another
/// org's galaxy (a different galaxy's policy set never contains this org's
/// `Actor::Team` rule).
fn default_org_actor_policy(repository_id: &RepositoryId, org_id: &str) -> VisibilityPolicy {
    VisibilityPolicy {
        id: PolicyId::generated(),
        repository_id: repository_id.clone(),
        name: "org-actor-content-sync".to_string(),
        priority: 0,
        rules: vec![PolicyRule {
            actor: Actor::Team(org_id.to_string()),
            token_id: None,
            environment_id: None,
            environment_kind: None,
            path_glob: None,
            key_glob: None,
            service_id: None,
            workspace_id: None,
            sensitivity: None,
            availability: None,
            actions: vec![
                PolicyAction::ReadBlob,
                PolicyAction::WriteChangeSet,
                PolicyAction::MergeChangeSet,
            ],
            decision: PolicyDecision::Allow,
            reason: Some(
                "org-scoped JWT actor: content sync for this org's own galaxy".to_string(),
            ),
        }],
    }
}

fn default_horizon_integration_policy(repository_id: &RepositoryId) -> VisibilityPolicy {
    VisibilityPolicy {
        id: PolicyId::generated(),
        repository_id: repository_id.clone(),
        name: "horizon-integration-deploy".to_string(),
        priority: 0,
        rules: vec![PolicyRule {
            actor: Actor::Integration(HORIZON_INTEGRATION_ACTOR_NAME.to_string()),
            token_id: None,
            environment_id: None,
            environment_kind: None,
            path_glob: None,
            key_glob: None,
            service_id: None,
            workspace_id: None,
            sensitivity: None,
            availability: None,
            actions: vec![
                PolicyAction::ReadBuildSource,
                PolicyAction::CreateProjection,
                PolicyAction::Deploy,
                PolicyAction::InjectVariable,
                PolicyAction::ManageDeployConfig,
            ],
            decision: PolicyDecision::Allow,
            reason: Some(
                "Horizon platform integration: deploy services and inject environment variables"
                    .to_string(),
            ),
        }],
    }
}

async fn create_repository(
    State(state): State<AppState>,
    Json(request): Json<CreateRepositoryRequest>,
) -> Result<Json<RepositoryRecord>, ApiError> {
    if request.name.trim().is_empty() {
        return Err(ApiError::bad_request("repository name is required"));
    }
    let repo = RepositoryRecord {
        id: RepositoryId::generated(),
        name: request.name,
        org_id: request.org_id,
    };
    let service_policy = default_astracollab_service_policy(&repo.id);
    let horizon_policy = default_horizon_integration_policy(&repo.id);
    let org_policy = repo
        .org_id
        .as_deref()
        .map(|org_id| default_org_actor_policy(&repo.id, org_id));
    if let Some(store) = &state.durable_store {
        let value = serde_json::to_value(&repo)
            .map_err(|error| ApiError::internal(format!("failed to encode repository: {error}")))?;
        store
            .put_repository_record(&repo.id, value)
            .await
            .map_err(storage_api_error)?;
        durable_put_resource(
            &state,
            Some(&repo.id),
            "policy",
            service_policy.id.as_str(),
            &service_policy,
        )
        .await?;
        durable_put_resource(
            &state,
            Some(&repo.id),
            "policy",
            horizon_policy.id.as_str(),
            &horizon_policy,
        )
        .await?;
        if let Some(org_policy) = &org_policy {
            durable_put_resource(
                &state,
                Some(&repo.id),
                "policy",
                org_policy.id.as_str(),
                org_policy,
            )
            .await?;
        }
    }
    {
        let mut registry = state
            .registry
            .write()
            .map_err(|_| ApiError::internal("registry lock poisoned"))?;
        registry.repositories.insert(repo.id.clone(), repo.clone());
        registry
            .policies
            .insert(service_policy.id.clone(), service_policy);
        registry
            .policies
            .insert(horizon_policy.id.clone(), horizon_policy);
        if let Some(org_policy) = org_policy {
            registry.policies.insert(org_policy.id.clone(), org_policy);
        }
    }
    persist_state(&state).await?;
    Ok(Json(repo))
}

async fn get_repository(
    State(state): State<AppState>,
    Path(repository_id): Path<String>,
) -> Result<Json<RepositoryRecord>, ApiError> {
    let id = RepositoryId::new(repository_id);
    if let Some(store) = &state.durable_store {
        let value = store
            .get_repository_record(&id)
            .await
            .map_err(storage_api_error)?;
        let repo = serde_json::from_value(value)
            .map_err(|error| ApiError::internal(format!("failed to decode repository: {error}")))?;
        return Ok(Json(repo));
    }
    let registry = state
        .registry
        .read()
        .map_err(|_| ApiError::internal("registry lock poisoned"))?;
    registry
        .repositories
        .get(&id)
        .cloned()
        .map(Json)
        .ok_or_else(|| ApiError::not_found(format!("repository {id} not found")))
}

async fn get_repository_by_name(
    State(state): State<AppState>,
    Path((owner, name)): Path<(String, String)>,
) -> Result<Json<RepositoryRecord>, ApiError> {
    let registry = state
        .registry
        .read()
        .map_err(|_| ApiError::internal("registry lock poisoned"))?;
    registry
        .repositories
        .values()
        .find(|record| record.org_id.as_deref() == Some(&owner) && record.name == name)
        .cloned()
        .map(Json)
        .ok_or_else(|| ApiError::not_found(format!("repository {owner}/{name} not found")))
}

async fn put_blob(
    State(state): State<AppState>,
    Path(repository_id): Path<String>,
    Json(request): Json<BlobPutRequest>,
) -> Result<Json<BlobPutResponse>, ApiError> {
    let repository_id = RepositoryId::new(repository_id);
    ensure_repo(&state, &repository_id)?;
    let bytes = request.bytes_utf8.into_bytes();
    if bytes.len() as u64 > MAX_IN_MEMORY_BLOB_BYTES {
        return Err(ApiError::bad_request(format!(
            "blob exceeds JSON API memory limit of {} bytes; use streaming sync",
            MAX_IN_MEMORY_BLOB_BYTES
        )));
    }
    let blob = ContentBlob::from_bytes(&bytes, request.media_type, request.visibility);
    if let Some(store) = &state.blob_store {
        store
            .put(&blob.hash, &bytes)
            .await
            .map_err(|error| ApiError::internal(format!("failed to persist blob: {error}")))?;
    }
    durable_put_resource(
        &state,
        Some(&repository_id),
        "blob",
        &blob_id(&blob.hash),
        &blob,
    )
    .await?;
    let cached_bytes = if state.blob_store.is_some() {
        Vec::new()
    } else {
        bytes
    };
    state
        .registry
        .write()
        .map_err(|_| ApiError::internal("registry lock poisoned"))?
        .blobs
        .insert(blob.hash.clone(), (blob.clone(), cached_bytes));
    persist_state(&state).await?;
    Ok(Json(BlobPutResponse { blob }))
}

async fn get_blob(
    State(state): State<AppState>,
    Path((repository_id, algorithm, digest)): Path<(String, String, String)>,
) -> Result<Json<BlobPutResponse>, ApiError> {
    let repository_id = RepositoryId::new(repository_id);
    ensure_repo(&state, &repository_id)?;
    let hash = ContentHash { algorithm, digest };
    if let Some(store) = &state.durable_store {
        let value = store
            .get_resource_scoped(Some(&repository_id), "blob", &blob_id(&hash))
            .await
            .map_err(storage_api_error)?;
        let blob = serde_json::from_value(value)
            .map_err(|error| ApiError::internal(format!("failed to decode blob: {error}")))?;
        return Ok(Json(BlobPutResponse { blob }));
    }
    if let Some(store) = &state.blob_store {
        let bytes = store.get(&hash).await.map_err(storage_api_error)?;
        let blob = ContentBlob::from_bytes(&bytes, None, BlobVisibility::Public);
        return Ok(Json(BlobPutResponse { blob }));
    }
    let registry = state
        .registry
        .read()
        .map_err(|_| ApiError::internal("registry lock poisoned"))?;
    registry
        .blobs
        .get(&hash)
        .map(|(blob, _)| Json(BlobPutResponse { blob: blob.clone() }))
        .ok_or_else(|| ApiError::not_found("blob not found"))
}

async fn get_blobs_batch(
    State(state): State<AppState>,
    Path(repository_id): Path<String>,
    Json(request): Json<BlobBatchRequest>,
) -> Result<Json<BlobBatchResponse>, ApiError> {
    let repository_id = RepositoryId::new(repository_id);
    ensure_repo(&state, &repository_id)?;
    if let Some(store) = &state.durable_store {
        let mut blobs = Vec::new();
        let mut missing = Vec::new();
        for hash in request.hashes {
            match store
                .get_resource_scoped(Some(&repository_id), "blob", &blob_id(&hash))
                .await
            {
                Ok(value) => blobs.push(serde_json::from_value(value).map_err(|error| {
                    ApiError::internal(format!("failed to decode blob: {error}"))
                })?),
                Err(NebulaError::NotFound(_)) => missing.push(hash),
                Err(error) => return Err(storage_api_error(error)),
            }
        }
        return Ok(Json(BlobBatchResponse { blobs, missing }));
    }
    let registry = state
        .registry
        .read()
        .map_err(|_| ApiError::internal("registry lock poisoned"))?;
    let mut blobs = Vec::new();
    let mut missing = Vec::new();
    for hash in request.hashes {
        if let Some((blob, _)) = registry.blobs.get(&hash) {
            blobs.push(blob.clone());
        } else {
            missing.push(hash);
        }
    }
    Ok(Json(BlobBatchResponse { blobs, missing }))
}

async fn get_blob_chunks(
    State(state): State<AppState>,
    Path((repository_id, algorithm, digest)): Path<(String, String, String)>,
) -> Result<Json<BlobChunksResponse>, ApiError> {
    let repository_id = RepositoryId::new(repository_id);
    ensure_repo(&state, &repository_id)?;
    let hash = ContentHash { algorithm, digest };
    if let Some(blob_store) = &state.blob_store {
        let bytes = blob_store.get(&hash).await.map_err(storage_api_error)?;
        let blob = if let Some(store) = &state.durable_store {
            let value = store
                .get_resource_scoped(Some(&repository_id), "blob", &blob_id(&hash))
                .await
                .map_err(storage_api_error)?;
            serde_json::from_value(value)
                .map_err(|error| ApiError::internal(format!("failed to decode blob: {error}")))?
        } else {
            ContentBlob::from_bytes(&bytes, None, BlobVisibility::Public)
        };
        let chunks = bytes
            .chunks(DEFAULT_BLOB_CHUNK_SIZE)
            .enumerate()
            .map(|(index, chunk)| {
                BlobChunk::from_bytes((index * DEFAULT_BLOB_CHUNK_SIZE) as u64, chunk)
            })
            .collect();
        return Ok(Json(BlobChunksResponse { blob, chunks }));
    }
    let registry = state
        .registry
        .read()
        .map_err(|_| ApiError::internal("registry lock poisoned"))?;
    let Some((blob, bytes)) = registry.blobs.get(&hash) else {
        return Err(ApiError::not_found("blob not found"));
    };
    let chunks = bytes
        .chunks(DEFAULT_BLOB_CHUNK_SIZE)
        .enumerate()
        .map(|(index, chunk)| {
            BlobChunk::from_bytes((index * DEFAULT_BLOB_CHUNK_SIZE) as u64, chunk)
        })
        .collect();
    Ok(Json(BlobChunksResponse {
        blob: blob.clone(),
        chunks,
    }))
}

async fn put_snapshot(
    State(state): State<AppState>,
    Path(repository_id): Path<String>,
    Json(snapshot): Json<TreeSnapshot>,
) -> Result<Json<TreeSnapshot>, ApiError> {
    let repository_id = RepositoryId::new(repository_id);
    ensure_repo(&state, &repository_id)?;
    if snapshot.repository_id != repository_id {
        return Err(ApiError::bad_request("snapshot repository mismatch"));
    }
    if let Some(store) = &state.durable_store {
        let value = serde_json::to_value(&snapshot)
            .map_err(|error| ApiError::internal(format!("failed to encode snapshot: {error}")))?;
        store
            .put_resource(
                Some(&repository_id),
                "snapshot",
                snapshot.id.as_str(),
                value,
            )
            .await
            .map_err(storage_api_error)?;
    }
    state
        .registry
        .write()
        .map_err(|_| ApiError::internal("registry lock poisoned"))?
        .snapshots
        .insert(snapshot.id.clone(), snapshot.clone());
    persist_state(&state).await?;
    Ok(Json(snapshot))
}

async fn get_snapshot(
    State(state): State<AppState>,
    Path((repository_id, snapshot_id)): Path<(String, String)>,
) -> Result<Json<TreeSnapshot>, ApiError> {
    let repository_id = RepositoryId::new(repository_id);
    ensure_repo(&state, &repository_id)?;
    if let Some(store) = &state.durable_store {
        let value = store
            .get_resource_scoped(Some(&repository_id), "snapshot", &snapshot_id)
            .await
            .map_err(storage_api_error)?;
        let snapshot: TreeSnapshot = serde_json::from_value(value)
            .map_err(|error| ApiError::internal(format!("failed to decode snapshot: {error}")))?;
        if snapshot.repository_id != repository_id {
            return Err(ApiError::not_found("snapshot not found"));
        }
        return Ok(Json(snapshot));
    }
    get_by_id(
        &state,
        |registry| {
            let snapshot = registry.snapshots.get(&TreeSnapshotId::new(snapshot_id))?;
            (snapshot.repository_id == repository_id).then(|| snapshot.clone())
        },
        "snapshot not found",
    )
}

async fn get_snapshot_tree(
    State(state): State<AppState>,
    Path((repository_id, snapshot_id)): Path<(String, String)>,
    Query(query): Query<TreeQuery>,
) -> Result<Json<TreeResponse>, ApiError> {
    let repository_id = RepositoryId::new(repository_id);
    ensure_repo(&state, &repository_id)?;
    let snapshot = get_snapshot_from_state(&state, TreeSnapshotId::new(snapshot_id))?;
    if snapshot.repository_id != repository_id {
        return Err(ApiError::not_found("snapshot not found"));
    }
    let path = query.path.unwrap_or_default();
    let node = TreeNode::from_entries(&path, &snapshot.entries)
        .map_err(|err| ApiError::bad_request(err.to_string()))?;
    Ok(Json(TreeResponse { node }))
}

async fn get_trees_batch(
    State(state): State<AppState>,
    Path(repository_id): Path<String>,
    Json(request): Json<TreeBatchRequest>,
) -> Result<Json<TreeBatchResponse>, ApiError> {
    let repository_id = RepositoryId::new(repository_id);
    ensure_repo(&state, &repository_id)?;
    let snapshot = get_snapshot_from_state(&state, request.snapshot_id)?;
    if snapshot.repository_id != repository_id {
        return Err(ApiError::not_found("snapshot not found"));
    }
    let mut nodes = Vec::new();
    let mut missing = Vec::new();
    for path in request.paths {
        match TreeNode::from_entries(&path, &snapshot.entries) {
            Ok(node) => nodes.push(node),
            Err(_) => missing.push(path),
        }
    }
    Ok(Json(TreeBatchResponse { nodes, missing }))
}

async fn put_ref(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(repository_id): Path<String>,
    Json(reference): Json<Ref>,
) -> Result<Json<Ref>, ApiError> {
    let repository_id = RepositoryId::new(repository_id);
    ensure_repo(&state, &repository_id)?;
    if reference.repository_id != repository_id {
        return Err(ApiError::bad_request("ref repository mismatch"));
    }
    if let Some(store) = &state.durable_store {
        let value = serde_json::to_value(&reference)
            .map_err(|error| ApiError::internal(format!("failed to encode ref: {error}")))?;
        let expected = headers
            .get("if-nebula-ref-target")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| serde_json::from_str::<serde_json::Value>(value).ok());
        if let Some(key) = idempotency_key(&headers) {
            store
                .commit_transaction(RegistryTransaction {
                    id: format!(
                        "tx_ref_{}_{}_{}",
                        reference.repository_id, reference.name, key
                    ),
                    repository_id: Some(reference.repository_id.clone()),
                    idempotency_key: Some(key),
                    mutations: Vec::new(),
                    ref_updates: vec![RefCompareAndSwap {
                        repository_id: reference.repository_id.clone(),
                        name: reference.name.clone(),
                        expected_target: expected,
                        next_ref: value,
                    }],
                    audit: RegistryMutationAudit {
                        actor: None,
                        action: "ref.update".to_string(),
                        reason: Some(format!("update ref {}", reference.name)),
                        created_at_unix_ms: now_unix_ms(),
                    },
                })
                .await
                .map_err(storage_api_error)?;
        } else {
            if !store
                .compare_and_swap_ref(&reference.repository_id, &reference.name, expected, value)
                .await
                .map_err(storage_api_error)?
            {
                return Err(ApiError {
                    status: StatusCode::CONFLICT,
                    message: "ref lease check failed".to_string(),
                });
            }
        }
    }
    {
        let mut registry = state
            .registry
            .write()
            .map_err(|_| ApiError::internal("registry lock poisoned"))?;
        registry.refs.insert(
            (reference.repository_id.clone(), reference.name.clone()),
            reference.clone(),
        );
    }
    persist_state(&state).await?;
    schedule_auto_deploys_for_ref(state.clone(), repository_id, reference.clone());
    Ok(Json(reference))
}

async fn get_ref(
    State(state): State<AppState>,
    Path((repository_id, name)): Path<(String, String)>,
) -> Result<Json<ResolveRefResponse>, ApiError> {
    let repository_id = RepositoryId::new(repository_id);
    ensure_repo(&state, &repository_id)?;
    if let Some(store) = &state.durable_store {
        let value = store
            .get_resource_scoped(Some(&repository_id), "ref", &ref_id(&repository_id, &name))
            .await
            .map_err(storage_api_error)?;
        let reference: Ref = serde_json::from_value(value)
            .map_err(|error| ApiError::internal(format!("failed to decode ref: {error}")))?;
        if reference.repository_id != repository_id {
            return Err(ApiError::not_found("ref not found"));
        }
        return Ok(Json(ResolveRefResponse { reference }));
    }
    let registry = state
        .registry
        .read()
        .map_err(|_| ApiError::internal("registry lock poisoned"))?;
    registry
        .refs
        .get(&(repository_id, name))
        .cloned()
        .map(|reference| Json(ResolveRefResponse { reference }))
        .ok_or_else(|| ApiError::not_found("ref not found"))
}

async fn create_workspace(
    State(state): State<AppState>,
    Path(repository_id): Path<String>,
    Json(request): Json<CreateWorkspaceRequest>,
) -> Result<Json<CreateWorkspaceResponse>, ApiError> {
    let repository_id = RepositoryId::new(repository_id);
    ensure_repo(&state, &repository_id)?;
    if request.repository_id != repository_id {
        return Err(ApiError::bad_request("workspace repository mismatch"));
    }
    let workspace = draft_workspace(request);
    durable_put_resource(
        &state,
        Some(&repository_id),
        "workspace",
        workspace.id.as_str(),
        &workspace,
    )
    .await?;
    state
        .registry
        .write()
        .map_err(|_| ApiError::internal("registry lock poisoned"))?
        .workspaces
        .insert(workspace.id.clone(), workspace.clone());
    persist_state(&state).await?;
    Ok(Json(CreateWorkspaceResponse { workspace }))
}

async fn put_changeset(
    State(state): State<AppState>,
    Path(repository_id): Path<String>,
    Json(changeset): Json<ChangeSet>,
) -> Result<Json<ChangeSet>, ApiError> {
    let repository_id = RepositoryId::new(repository_id);
    ensure_repo(&state, &repository_id)?;
    if changeset.repository_id != repository_id {
        return Err(ApiError::bad_request("changeset repository mismatch"));
    }
    durable_put_resource(
        &state,
        Some(&repository_id),
        "changeset",
        changeset.id.as_str(),
        &changeset,
    )
    .await?;
    state
        .registry
        .write()
        .map_err(|_| ApiError::internal("registry lock poisoned"))?
        .changesets
        .insert(changeset.id.clone(), changeset.clone());
    persist_state(&state).await?;
    Ok(Json(changeset))
}

async fn get_changeset(
    State(state): State<AppState>,
    Path((repository_id, changeset_id)): Path<(String, String)>,
) -> Result<Json<ChangeSet>, ApiError> {
    let repository_id = RepositoryId::new(repository_id);
    ensure_repo(&state, &repository_id)?;
    if let Some(changeset) =
        durable_get_resource(&state, Some(&repository_id), "changeset", &changeset_id).await?
    {
        return Ok(Json(changeset));
    }
    get_by_id(
        &state,
        |registry| {
            let changeset = registry.changesets.get(&ChangeSetId::new(changeset_id))?;
            (changeset.repository_id == repository_id).then(|| changeset.clone())
        },
        "changeset not found",
    )
}

async fn create_proposal(
    State(state): State<AppState>,
    Path(repository_id): Path<String>,
    Json(request): Json<CreateProposalRequest>,
) -> Result<Json<CreateProposalResponse>, ApiError> {
    let repository_id = RepositoryId::new(repository_id);
    ensure_repo(&state, &repository_id)?;
    if request.repository_id != repository_id {
        return Err(ApiError::bad_request("proposal repository mismatch"));
    }
    let proposal = draft_proposal(request);
    durable_put_resource(
        &state,
        Some(&repository_id),
        "proposal",
        proposal.id.as_str(),
        &proposal,
    )
    .await?;
    state
        .registry
        .write()
        .map_err(|_| ApiError::internal("registry lock poisoned"))?
        .proposals
        .insert(proposal.id.clone(), proposal.clone());
    persist_state(&state).await?;
    Ok(Json(CreateProposalResponse { proposal }))
}

async fn get_proposal(
    State(state): State<AppState>,
    Path((repository_id, proposal_id)): Path<(String, String)>,
) -> Result<Json<Proposal>, ApiError> {
    let repository_id = RepositoryId::new(repository_id);
    ensure_repo(&state, &repository_id)?;
    if let Some(proposal) =
        durable_get_resource(&state, Some(&repository_id), "proposal", &proposal_id).await?
    {
        return Ok(Json(proposal));
    }
    get_by_id(
        &state,
        |registry| {
            let proposal = registry.proposals.get(&ProposalId::new(proposal_id))?;
            (proposal.repository_id == repository_id).then(|| proposal.clone())
        },
        "proposal not found",
    )
}

async fn list_policies(
    State(state): State<AppState>,
    Path(repository_id): Path<String>,
) -> Result<Json<Vec<VisibilityPolicy>>, ApiError> {
    let repository_id = RepositoryId::new(repository_id);
    ensure_repo(&state, &repository_id)?;
    let mut policies = {
        let registry = state
            .registry
            .read()
            .map_err(|_| ApiError::internal("registry lock poisoned"))?;
        registry
            .policies
            .values()
            .filter(|policy| policy.repository_id == repository_id)
            .cloned()
            .collect::<Vec<_>>()
    };
    policies.sort_by(|a, b| a.id.as_str().cmp(b.id.as_str()));
    Ok(Json(policies))
}

async fn delete_policy(
    State(state): State<AppState>,
    Path((repository_id, policy_id)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let repository_id = RepositoryId::new(repository_id);
    ensure_repo(&state, &repository_id)?;
    let policy_id = PolicyId::new(policy_id);
    let removed = {
        let mut registry = state
            .registry
            .write()
            .map_err(|_| ApiError::internal("registry lock poisoned"))?;
        match registry.policies.get(&policy_id) {
            Some(policy) if policy.repository_id == repository_id => {
                registry.policies.remove(&policy_id);
                true
            }
            Some(_) => return Err(ApiError::bad_request("policy repository mismatch")),
            None => false,
        }
    };
    if !removed {
        return Err(ApiError::not_found("policy not found"));
    }
    durable_delete_resource(&state, Some(&repository_id), "policy", policy_id.as_str()).await?;
    persist_state(&state).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn put_policy(
    State(state): State<AppState>,
    Path(repository_id): Path<String>,
    Json(policy): Json<VisibilityPolicy>,
) -> Result<Json<VisibilityPolicy>, ApiError> {
    let repository_id = RepositoryId::new(repository_id);
    ensure_repo(&state, &repository_id)?;
    if policy.repository_id != repository_id {
        return Err(ApiError::bad_request("policy repository mismatch"));
    }
    let validation = validate_cedar_policy_document(&cedar_document_for_visibility_policy(&policy));
    if !validation.valid {
        return Err(ApiError::bad_request(format!(
            "invalid Cedar policy boundary: {}",
            validation
                .error
                .unwrap_or_else(|| "unknown error".to_string())
        )));
    }
    durable_put_resource(
        &state,
        Some(&repository_id),
        "policy",
        policy.id.as_str(),
        &policy,
    )
    .await?;
    state
        .registry
        .write()
        .map_err(|_| ApiError::internal("registry lock poisoned"))?
        .policies
        .insert(policy.id.clone(), policy.clone());
    persist_state(&state).await?;
    Ok(Json(policy))
}

async fn put_cedar_policy_document(
    State(state): State<AppState>,
    Path(repository_id): Path<String>,
    Json(document): Json<StoredCedarPolicyDocument>,
) -> Result<Json<StoredCedarPolicyDocument>, ApiError> {
    let repository_id = RepositoryId::new(repository_id);
    ensure_repo(&state, &repository_id)?;
    if document.repository_id != repository_id {
        return Err(ApiError::bad_request("Cedar policy repository mismatch"));
    }
    let policy_document = nebula_policy::CedarPolicyDocument {
        id: document.id.clone(),
        repository_id: document.repository_id.clone(),
        text: document.text.clone(),
        version: document.version,
        enabled: document.enabled,
    };
    let validation = validate_cedar_policy_document(&policy_document);
    if !validation.valid {
        return Err(ApiError::bad_request(
            validation
                .error
                .unwrap_or_else(|| "invalid Cedar policy".to_string()),
        ));
    }
    durable_put_resource(
        &state,
        Some(&repository_id),
        "cedar_policy_document",
        &document.id,
        &document,
    )
    .await?;
    state
        .registry
        .write()
        .map_err(|_| ApiError::internal("registry lock poisoned"))?
        .cedar_policy_documents
        .insert(document.id.clone(), document.clone());
    persist_state(&state).await?;
    Ok(Json(document))
}

async fn list_environments(
    State(state): State<AppState>,
    Path(repository_id): Path<String>,
) -> Result<Json<Vec<Environment>>, ApiError> {
    let repository_id = RepositoryId::new(repository_id);
    ensure_repo(&state, &repository_id)?;
    let registry = state
        .registry
        .read()
        .map_err(|_| ApiError::internal("registry lock poisoned"))?;
    let environments = registry
        .environments
        .values()
        .filter(|environment| environment.repository_id == repository_id)
        .cloned()
        .collect::<Vec<_>>();
    Ok(Json(environments))
}

async fn put_environment(
    State(state): State<AppState>,
    Path(repository_id): Path<String>,
    Json(environment): Json<Environment>,
) -> Result<Json<Environment>, ApiError> {
    let repository_id = RepositoryId::new(repository_id);
    ensure_repo(&state, &repository_id)?;
    if environment.repository_id != repository_id {
        return Err(ApiError::bad_request("environment repository mismatch"));
    }
    durable_put_resource(
        &state,
        Some(&repository_id),
        "environment",
        environment.id.as_str(),
        &environment,
    )
    .await?;
    state
        .registry
        .write()
        .map_err(|_| ApiError::internal("registry lock poisoned"))?
        .environments
        .insert(environment.id.clone(), environment.clone());
    persist_state(&state).await?;
    Ok(Json(environment))
}

async fn list_environment_variables(
    State(state): State<AppState>,
    Path((repository_id, environment_id)): Path<(String, String)>,
) -> Result<Json<ListEnvironmentVariablesResponse>, ApiError> {
    let repository_id = RepositoryId::new(repository_id);
    let environment_id = EnvironmentId::new(environment_id);
    ensure_repo(&state, &repository_id)?;
    ensure_environment(&state, &repository_id, &environment_id).await?;
    let variables = {
        let registry = state
            .registry
            .read()
            .map_err(|_| ApiError::internal("registry lock poisoned"))?;
        registry
            .environment_variables
            .values()
            .filter(|variable| {
                variable.repository_id == repository_id && variable.environment_id == environment_id
            })
            .map(|variable| {
                let current_version = variable
                    .current_version_id
                    .as_ref()
                    .and_then(|id| registry.environment_variable_versions.get(id))
                    .map(|version| variable_version_view(version, false));
                EnvironmentVariableView {
                    variable: variable.clone(),
                    current_version,
                }
            })
            .collect::<Vec<_>>()
    };
    Ok(Json(ListEnvironmentVariablesResponse { variables }))
}

async fn upsert_environment_variable(
    State(state): State<AppState>,
    claims: Option<Extension<VerifiedClaims>>,
    Path((repository_id, environment_id)): Path<(String, String)>,
    Json(request): Json<UpsertEnvironmentVariableRequest>,
) -> Result<Json<UpsertEnvironmentVariableResponse>, ApiError> {
    let repository_id = RepositoryId::new(repository_id);
    let environment_id = EnvironmentId::new(environment_id);
    ensure_repo(&state, &repository_id)?;
    let environment = ensure_environment(&state, &repository_id, &environment_id).await?;
    let key = normalize_variable_key(&request.key)?;
    let actor = request
        .actor
        .clone()
        .or_else(|| claims.map(|Extension(claims)| claims.actor))
        .unwrap_or(Actor::Public);
    let scope = request.scope.clone().unwrap_or(VariableScope::Shared);
    let variable_id = EnvironmentVariable::stable_id(&repository_id, &environment_id, &scope, &key);
    let now = now_unix_ms();
    let existing = {
        let registry = state
            .registry
            .read()
            .map_err(|_| ApiError::internal("registry lock poisoned"))?;
        registry.environment_variables.get(&variable_id).cloned()
    };
    let sensitivity = request
        .sensitivity
        .clone()
        .unwrap_or_else(|| default_variable_sensitivity(&key, &environment.kind));
    let value_kind = request
        .value_kind
        .clone()
        .unwrap_or_else(|| default_variable_value_kind(&sensitivity, request.reference.as_ref()));
    let storage_mode = request
        .storage_mode
        .clone()
        .unwrap_or_else(|| default_secret_storage_mode(&sensitivity, &value_kind));
    let availability = if request.availability.is_empty() {
        vec![VariableAvailability::Build, VariableAvailability::Runtime]
    } else {
        request.availability.clone()
    };
    let mut variable = existing.clone().unwrap_or(EnvironmentVariable {
        id: variable_id.clone(),
        repository_id: repository_id.clone(),
        workspace_id: request.workspace_id.clone(),
        environment_id: environment_id.clone(),
        scope: scope.clone(),
        key: key.clone(),
        value_kind: value_kind.clone(),
        availability: availability.clone(),
        sensitivity: sensitivity.clone(),
        storage_mode: storage_mode.clone(),
        current_version_id: None,
        reference: request.reference.clone(),
        created_by: Some(actor.clone()),
        updated_by: Some(actor.clone()),
        created_at_unix_ms: now,
        updated_at_unix_ms: now,
    });
    variable.workspace_id = request.workspace_id.clone().or(variable.workspace_id);
    variable.scope = scope;
    variable.key = key.clone();
    variable.value_kind = value_kind.clone();
    variable.availability = availability;
    variable.sensitivity = sensitivity.clone();
    variable.storage_mode = storage_mode.clone();
    variable.reference = request.reference.clone();
    variable.updated_by = Some(actor.clone());
    variable.updated_at_unix_ms = now;

    let mut version = None;
    if let Some(value) = request.value.as_ref() {
        let created = create_environment_variable_version(
            &state,
            &repository_id,
            &variable_id,
            &key,
            &value_kind,
            &sensitivity,
            &storage_mode,
            value,
            actor.clone(),
        )
        .await?;
        if !request.stage {
            variable.current_version_id = Some(created.id.clone());
        }
        version = Some(created);
    }

    let change = EnvironmentVariableChange {
        id: format!("envchg_{}_{}", variable.id.as_str(), now),
        repository_id: repository_id.clone(),
        variable_id: variable.id.clone(),
        actor,
        action: if existing.is_some() {
            "update".to_string()
        } else {
            "create".to_string()
        },
        state: if request.stage {
            VariableChangeState::Staged
        } else {
            VariableChangeState::Applied
        },
        before_version_id: existing.and_then(|variable| variable.current_version_id),
        after_version_id: version.as_ref().map(|version| version.id.clone()),
        reason: request.reason.clone(),
        created_at_unix_ms: now,
    };

    durable_put_resource(
        &state,
        Some(&repository_id),
        "environment_variable",
        variable.id.as_str(),
        &variable,
    )
    .await?;
    if let Some(version) = &version {
        durable_put_resource(
            &state,
            Some(&repository_id),
            "environment_variable_version",
            version.id.as_str(),
            version,
        )
        .await?;
    }
    durable_put_resource(
        &state,
        Some(&repository_id),
        "environment_variable_change",
        &change.id,
        &change,
    )
    .await?;
    {
        let mut registry = state
            .registry
            .write()
            .map_err(|_| ApiError::internal("registry lock poisoned"))?;
        if let Some(version) = version.clone() {
            registry
                .environment_variable_versions
                .insert(version.id.clone(), version);
        }
        registry
            .environment_variable_changes
            .insert(change.id.clone(), change.clone());
        registry
            .environment_variables
            .insert(variable.id.clone(), variable.clone());
    }
    persist_state(&state).await?;
    let current_version = if let Some(version_id) = variable.current_version_id.as_ref() {
        let current =
            if let Some(version) = version.as_ref().filter(|version| &version.id == version_id) {
                Some(version.clone())
            } else {
                state
                    .registry
                    .read()
                    .map_err(|_| ApiError::internal("registry lock poisoned"))?
                    .environment_variable_versions
                    .get(version_id)
                    .cloned()
            };
        current.map(|version| variable_version_view(&version, false))
    } else {
        None
    };
    Ok(Json(UpsertEnvironmentVariableResponse {
        variable: EnvironmentVariableView {
            current_version,
            variable,
        },
        change: Some(change),
    }))
}

async fn inject_environment_variables(
    State(state): State<AppState>,
    Path((repository_id, environment_id)): Path<(String, String)>,
    Json(request): Json<InjectEnvironmentVariablesRequest>,
) -> Result<Json<InjectEnvironmentVariablesResponse>, ApiError> {
    let repository_id = RepositoryId::new(repository_id);
    let environment_id = EnvironmentId::new(environment_id);
    ensure_repo(&state, &repository_id)?;
    ensure_environment(&state, &repository_id, &environment_id).await?;
    let variables = {
        let registry = state
            .registry
            .read()
            .map_err(|_| ApiError::internal("registry lock poisoned"))?;
        registry
            .environment_variables
            .values()
            .filter(|variable| variable.repository_id == repository_id)
            .filter(|variable| variable.environment_id == environment_id)
            .filter(|variable| {
                request.service_id.as_ref().is_none_or(|service_id| {
                    matches!(&variable.scope, VariableScope::Shared)
                        || matches!(&variable.scope, VariableScope::Service { service_id: id } if id == service_id)
                })
            })
            .filter(|variable| {
                request
                    .availability
                    .as_ref()
                    .is_none_or(|availability| variable.availability.contains(availability))
            })
            .filter_map(|variable| {
                let version_id = variable.current_version_id.as_ref()?;
                let version = registry.environment_variable_versions.get(version_id)?;
                Some((variable.clone(), version.clone()))
            })
            .collect::<Vec<_>>()
    };
    let mut injected = Vec::new();
    let mut redaction_tokens = BTreeMap::new();
    for (variable, mut version) in variables {
        let value = decrypt_environment_variable_value(&state, &version)?;
        if variable.sensitivity.is_write_only() {
            redaction_tokens.insert(variable.key.clone(), redaction_values(&value));
        }
        version.last_injected_at_unix_ms = Some(now_unix_ms());
        version.last_used_by_deploy_id = request.deploy_intent_id.clone();
        durable_put_resource(
            &state,
            Some(&repository_id),
            "environment_variable_version",
            version.id.as_str(),
            &version,
        )
        .await?;
        injected.push(InjectedEnvironmentVariable {
            key: variable.key.clone(),
            value,
            variable_id: variable.id,
            version_id: version.id.clone(),
            sensitivity: variable.sensitivity,
            availability: variable.availability,
        });
        state
            .registry
            .write()
            .map_err(|_| ApiError::internal("registry lock poisoned"))?
            .environment_variable_versions
            .insert(version.id.clone(), version);
    }
    Ok(Json(InjectEnvironmentVariablesResponse {
        variables: injected,
        redaction_tokens,
    }))
}

async fn export_environment_variable(
    State(state): State<AppState>,
    Path((repository_id, _environment_id, variable_id)): Path<(String, String, String)>,
) -> Result<Json<InjectedEnvironmentVariable>, ApiError> {
    let repository_id = RepositoryId::new(repository_id);
    let variable_id = EnvironmentVariableId::new(variable_id);
    ensure_repo(&state, &repository_id)?;
    let (variable, version) = {
        let registry = state
            .registry
            .read()
            .map_err(|_| ApiError::internal("registry lock poisoned"))?;
        let variable = registry
            .environment_variables
            .get(&variable_id)
            .filter(|variable| variable.repository_id == repository_id)
            .cloned()
            .ok_or_else(|| ApiError::not_found("environment variable not found"))?;
        let version_id = variable
            .current_version_id
            .as_ref()
            .ok_or_else(|| ApiError::not_found("environment variable has no value"))?;
        let version = registry
            .environment_variable_versions
            .get(version_id)
            .cloned()
            .ok_or_else(|| ApiError::not_found("environment variable value not found"))?;
        (variable, version)
    };
    let value = decrypt_environment_variable_value(&state, &version)?;
    Ok(Json(InjectedEnvironmentVariable {
        key: variable.key,
        value,
        variable_id: variable.id,
        version_id: version.id,
        sensitivity: variable.sensitivity,
        availability: variable.availability,
    }))
}

async fn put_integration(
    State(state): State<AppState>,
    Path(repository_id): Path<String>,
    Json(integration): Json<IntegrationActor>,
) -> Result<Json<IntegrationActor>, ApiError> {
    let repository_id = RepositoryId::new(repository_id);
    ensure_repo(&state, &repository_id)?;
    durable_put_resource(
        &state,
        Some(&repository_id),
        "integration",
        &integration.provider,
        &integration,
    )
    .await?;
    state
        .registry
        .write()
        .map_err(|_| ApiError::internal("registry lock poisoned"))?
        .integrations
        .insert(integration.provider.clone(), integration.clone());
    persist_state(&state).await?;
    Ok(Json(integration))
}

async fn put_merge_intent(
    State(state): State<AppState>,
    Path(repository_id): Path<String>,
    Json(intent): Json<MergeIntent>,
) -> Result<Json<MergeIntent>, ApiError> {
    let repository_id = RepositoryId::new(repository_id);
    ensure_repo(&state, &repository_id)?;
    if intent.repository_id != repository_id {
        return Err(ApiError::bad_request("merge intent repository mismatch"));
    }
    durable_put_resource(
        &state,
        Some(&repository_id),
        "merge_intent",
        intent.id.as_str(),
        &intent,
    )
    .await?;
    state
        .registry
        .write()
        .map_err(|_| ApiError::internal("registry lock poisoned"))?
        .merge_intents
        .insert(intent.id.clone(), intent.clone());
    persist_state(&state).await?;
    Ok(Json(intent))
}

async fn put_release_gate(
    State(state): State<AppState>,
    Path(repository_id): Path<String>,
    Json(gate): Json<ReleaseGate>,
) -> Result<Json<ReleaseGate>, ApiError> {
    let repository_id = RepositoryId::new(repository_id);
    ensure_repo(&state, &repository_id)?;
    if gate.repository_id != repository_id {
        return Err(ApiError::bad_request("release gate repository mismatch"));
    }
    durable_put_resource(
        &state,
        Some(&repository_id),
        "release_gate",
        gate.id.as_str(),
        &gate,
    )
    .await?;
    state
        .registry
        .write()
        .map_err(|_| ApiError::internal("registry lock poisoned"))?
        .release_gates
        .insert(gate.id.clone(), gate.clone());
    persist_state(&state).await?;
    Ok(Json(gate))
}

async fn put_vector_manifest(
    State(state): State<AppState>,
    Path(repository_id): Path<String>,
    Json(manifest): Json<VectorIndexManifest>,
) -> Result<Json<VectorIndexManifest>, ApiError> {
    let repository_id = RepositoryId::new(repository_id);
    ensure_repo(&state, &repository_id)?;
    if manifest.repository_id != repository_id {
        return Err(ApiError::bad_request("vector manifest repository mismatch"));
    }
    durable_put_resource(
        &state,
        Some(&repository_id),
        "vector_manifest",
        manifest.id.as_str(),
        &manifest,
    )
    .await?;
    state
        .registry
        .write()
        .map_err(|_| ApiError::internal("registry lock poisoned"))?
        .vector_manifests
        .insert(manifest.id.clone(), manifest.clone());
    persist_state(&state).await?;
    Ok(Json(manifest))
}

async fn create_vector_index(
    State(state): State<AppState>,
    Path(repository_id): Path<String>,
    Json(request): Json<VectorIndexRequest>,
) -> Result<Json<VectorIndexResponse>, ApiError> {
    let repository_id = RepositoryId::new(repository_id);
    ensure_repo(&state, &repository_id)?;
    let Some(vector_store) = &state.vector_store else {
        return Err(ApiError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            message: "vector store is not configured".to_string(),
        });
    };
    let snapshot_id = request
        .snapshot_id
        .clone()
        .ok_or_else(|| ApiError::bad_request("snapshot_id is required"))?;
    let snapshot = get_snapshot_for_repository(&state, &repository_id, snapshot_id).await?;
    let chunks = snapshot
        .entries
        .iter()
        .filter_map(|entry| {
            let hash = entry.hash.clone()?;
            Some(CodeEmbeddingChunk {
                manifest_id: VectorIndexManifestId::new("__pending__"),
                path: entry.path.clone(),
                start_line: None,
                end_line: None,
                content_hash: hash,
            })
        })
        .collect::<Vec<_>>();
    let manifest = VectorIndexManifest {
        id: VectorIndexManifestId::generated(),
        repository_id: repository_id.clone(),
        snapshot_id: snapshot.id.clone(),
        projection_id: request.projection_id,
        index_version: "nebula-code-index-v1".to_string(),
        chunk_count: chunks.len() as u64,
        embedding_model: "experimental-path-content-hash-v1".to_string(),
        promoted_at_unix_ms: Some(now_unix_ms()),
        tombstoned_at_unix_ms: None,
    };
    let chunks = chunks
        .into_iter()
        .map(|mut chunk| {
            chunk.manifest_id = manifest.id.clone();
            chunk
        })
        .collect::<Vec<_>>();
    vector_store
        .put_manifest(manifest.clone())
        .await
        .map_err(storage_api_error)?;
    vector_store
        .put_chunks(&manifest, chunks)
        .await
        .map_err(storage_api_error)?;
    let job = VectorIndexJob {
        id: VectorIndexJobId::generated(),
        repository_id: repository_id.clone(),
        snapshot_id: snapshot.id,
        projection_id: manifest.projection_id.clone(),
        requested_by: request.actor,
        worker_kind: "registry-inline-path-index".to_string(),
        state: VectorIndexJobState::Ready,
        manifest_id: Some(manifest.id.clone()),
        error_message: None,
        queued_at_unix_ms: now_unix_ms(),
        started_at_unix_ms: Some(now_unix_ms()),
        completed_at_unix_ms: Some(now_unix_ms()),
    };
    durable_put_resource(
        &state,
        Some(&repository_id),
        "vector_manifest",
        manifest.id.as_str(),
        &manifest,
    )
    .await?;
    durable_put_resource(
        &state,
        Some(&repository_id),
        "vector_index_job",
        job.id.as_str(),
        &job,
    )
    .await?;
    {
        let mut registry = state
            .registry
            .write()
            .map_err(|_| ApiError::internal("registry lock poisoned"))?;
        registry
            .vector_manifests
            .insert(manifest.id.clone(), manifest.clone());
        registry
            .vector_index_jobs
            .insert(job.id.clone(), job.clone());
    }
    persist_state(&state).await?;
    Ok(Json(VectorIndexResponse { manifest, job }))
}

async fn search_vector_index(
    State(state): State<AppState>,
    Path(repository_id): Path<String>,
    Json(request): Json<VectorSearchRequest>,
) -> Result<Json<VectorSearchResponse>, ApiError> {
    let repository_id = RepositoryId::new(repository_id);
    ensure_repo(&state, &repository_id)?;
    let Some(vector_store) = &state.vector_store else {
        return Err(ApiError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            message: "vector store is not configured".to_string(),
        });
    };
    let manifest = if let Some(manifest_id) = &request.manifest_id {
        vector_store
            .get_manifest(&repository_id, manifest_id)
            .await
            .map_err(storage_api_error)?
    } else if let Some(snapshot_id) = &request.snapshot_id {
        vector_store
            .get_manifest_for_snapshot(snapshot_id)
            .await
            .map_err(storage_api_error)?
            .filter(|manifest| manifest.repository_id == repository_id)
    } else {
        return Err(ApiError::bad_request(
            "manifest_id or snapshot_id is required for vector search",
        ));
    }
    .ok_or_else(|| ApiError::not_found("vector manifest not found"))?;
    let top_k = request.top_k.unwrap_or(10).clamp(1, 100);
    let chunks = vector_store
        .search_chunks(&repository_id, &manifest.id, &request.query, top_k)
        .await
        .map_err(storage_api_error)?;
    let hits = chunks
        .into_iter()
        .map(|chunk| VectorSearchHit {
            path: chunk.path.clone(),
            start_line: chunk.start_line,
            end_line: chunk.end_line,
            score: if request.query.is_empty() { 0.5 } else { 1.0 },
            snippet: format!(
                "experimental path/hash index content {}",
                chunk.content_hash.digest
            ),
        })
        .collect();
    Ok(Json(VectorSearchResponse {
        manifest_id: manifest.id,
        hits,
    }))
}

async fn explain_vector_chunk(
    State(state): State<AppState>,
    Path(repository_id): Path<String>,
    Json(request): Json<VectorExplainRequest>,
) -> Result<Json<VectorExplainResponse>, ApiError> {
    let repository_id = RepositoryId::new(repository_id);
    ensure_repo(&state, &repository_id)?;
    let Some(vector_store) = &state.vector_store else {
        return Err(ApiError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            message: "vector store is not configured".to_string(),
        });
    };
    let chunk = vector_store
        .get_chunks(&repository_id, &request.manifest_id)
        .await
        .map_err(storage_api_error)?
        .into_iter()
        .find(|chunk| chunk.path == request.path);
    Ok(Json(VectorExplainResponse {
        manifest_id: request.manifest_id,
        path: request.path,
        chunk,
    }))
}

async fn put_projection(
    State(state): State<AppState>,
    Path(repository_id): Path<String>,
    Json(projection): Json<Projection>,
) -> Result<Json<Projection>, ApiError> {
    let repository_id = RepositoryId::new(repository_id);
    ensure_repo(&state, &repository_id)?;
    if projection.repository_id != repository_id {
        return Err(ApiError::bad_request("projection repository mismatch"));
    }
    durable_put_resource(
        &state,
        Some(&repository_id),
        "projection",
        projection.id.as_str(),
        &projection,
    )
    .await?;
    state
        .registry
        .write()
        .map_err(|_| ApiError::internal("registry lock poisoned"))?
        .projections
        .insert(projection.id.clone(), projection.clone());
    persist_state(&state).await?;
    Ok(Json(projection))
}

async fn put_git_export(
    State(state): State<AppState>,
    Path(repository_id): Path<String>,
    Json(export): Json<GitExport>,
) -> Result<Json<GitExport>, ApiError> {
    let repository_id = RepositoryId::new(repository_id);
    ensure_repo(&state, &repository_id)?;
    durable_put_resource(
        &state,
        Some(&repository_id),
        "git_export",
        export.id.as_str(),
        &export,
    )
    .await?;
    state
        .registry
        .write()
        .map_err(|_| ApiError::internal("registry lock poisoned"))?
        .git_exports
        .insert(export.id.clone(), export.clone());
    persist_state(&state).await?;
    Ok(Json(export))
}

async fn put_operation(
    State(state): State<AppState>,
    Path(repository_id): Path<String>,
    Json(operation): Json<Operation>,
) -> Result<Json<Operation>, ApiError> {
    let repository_id = RepositoryId::new(repository_id);
    ensure_repo(&state, &repository_id)?;
    if operation.repository_id != repository_id {
        return Err(ApiError::bad_request("operation repository mismatch"));
    }
    durable_put_resource(
        &state,
        Some(&repository_id),
        "operation",
        operation.id.as_str(),
        &operation,
    )
    .await?;
    state
        .registry
        .write()
        .map_err(|_| ApiError::internal("registry lock poisoned"))?
        .operations
        .insert(operation.id.clone(), operation.clone());
    persist_state(&state).await?;
    Ok(Json(operation))
}

async fn put_deployment_grant(
    State(state): State<AppState>,
    Path(repository_id): Path<String>,
    Json(grant): Json<DeploymentGrant>,
) -> Result<Json<DeploymentGrant>, ApiError> {
    let repository_id = RepositoryId::new(repository_id);
    ensure_repo(&state, &repository_id)?;
    durable_put_resource(
        &state,
        Some(&repository_id),
        "deployment_grant",
        grant.id.as_str(),
        &grant,
    )
    .await?;
    state
        .registry
        .write()
        .map_err(|_| ApiError::internal("registry lock poisoned"))?
        .deployment_grants
        .insert(grant.id.clone(), grant.clone());
    persist_state(&state).await?;
    Ok(Json(grant))
}

async fn get_deploy_config(
    State(state): State<AppState>,
    Path((repository_id, service_id)): Path<(String, String)>,
) -> Result<Json<RepositoryDeployConfigView>, ApiError> {
    let repository_id = RepositoryId::new(repository_id);
    ensure_repo(&state, &repository_id)?;
    let config = {
        let registry = state
            .registry
            .read()
            .map_err(|_| ApiError::internal("registry lock poisoned"))?;
        registry
            .deploy_configs
            .get(&(repository_id, service_id))
            .cloned()
    };
    let config = config.ok_or_else(|| ApiError::not_found("deploy config not set"))?;
    Ok(Json(RepositoryDeployConfigView {
        provider_key: config.provider_key,
        deploy_url: config.deploy_url,
        service_id: config.service_id,
        environment_id: config.environment_id,
        environment_name: config.environment_name,
        context_path: config.context_path,
        env_policy: config.env_policy,
        auto_deploy: config.auto_deploy,
    }))
}

async fn put_deploy_config(
    State(state): State<AppState>,
    Path((repository_id, service_id)): Path<(String, String)>,
    Json(request): Json<SetRepositoryDeployConfigRequest>,
) -> Result<Json<RepositoryDeployConfigView>, ApiError> {
    let repository_id = RepositoryId::new(repository_id);
    ensure_repo(&state, &repository_id)?;
    if request.deploy_url.trim().is_empty() {
        return Err(ApiError::bad_request("deploy_url is required"));
    }
    if request.signing_secret.len() < 16 {
        return Err(ApiError::bad_request(
            "signing_secret must be at least 16 characters",
        ));
    }
    if service_id.trim().is_empty() {
        return Err(ApiError::bad_request("service_id is required"));
    }
    let config = RepositoryDeployConfig {
        repository_id: repository_id.clone(),
        provider_key: request.provider_key.clone(),
        deploy_url: request.deploy_url.clone(),
        signing_secret: request.signing_secret,
        service_id: service_id.clone(),
        environment_id: request.environment_id.clone(),
        environment_name: request.environment_name.clone(),
        context_path: request.context_path.clone(),
        env_policy: request.env_policy.clone(),
        auto_deploy: request.auto_deploy,
    };
    durable_put_resource(
        &state,
        Some(&repository_id),
        "deploy_config",
        &format!("{repository_id}:{service_id}"),
        &config,
    )
    .await?;
    state
        .registry
        .write()
        .map_err(|_| ApiError::internal("registry lock poisoned"))?
        .deploy_configs
        .insert((repository_id, service_id), config.clone());
    persist_state(&state).await?;
    Ok(Json(RepositoryDeployConfigView {
        provider_key: config.provider_key,
        deploy_url: config.deploy_url,
        service_id: config.service_id,
        environment_id: config.environment_id,
        environment_name: config.environment_name,
        context_path: config.context_path,
        env_policy: config.env_policy,
        auto_deploy: config.auto_deploy,
    }))
}

async fn delete_deploy_config(
    State(state): State<AppState>,
    Path((repository_id, service_id)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let repository_id = RepositoryId::new(repository_id);
    ensure_repo(&state, &repository_id)?;
    let removed = state
        .registry
        .write()
        .map_err(|_| ApiError::internal("registry lock poisoned"))?
        .deploy_configs
        .remove(&(repository_id.clone(), service_id.clone()))
        .is_some();
    if !removed {
        return Err(ApiError::not_found("deploy config not set"));
    }
    durable_delete_resource(
        &state,
        Some(&repository_id),
        "deploy_config",
        &format!("{repository_id}:{service_id}"),
    )
    .await?;
    persist_state(&state).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn create_deploy_intent(
    State(state): State<AppState>,
    Path(repository_id): Path<String>,
    Json(request): Json<CreateDeployIntentRequest>,
) -> Result<Json<DeployIntentResponse>, ApiError> {
    let repository_id = RepositoryId::new(repository_id);
    ensure_repo(&state, &repository_id)?;
    let intent = execute_create_deploy_intent(&state, repository_id, request).await?;
    Ok(Json(DeployIntentResponse { intent }))
}

async fn execute_create_deploy_intent(
    state: &AppState,
    repository_id: RepositoryId,
    request: CreateDeployIntentRequest,
) -> Result<DeployIntent, ApiError> {
    let projection = {
        let registry = state
            .registry
            .read()
            .map_err(|_| ApiError::internal("registry lock poisoned"))?;
        registry.projections.get(&request.projection_id).cloned()
    }
    .ok_or_else(|| ApiError::not_found("projection not found"))?;
    if projection.repository_id != repository_id {
        return Err(ApiError::bad_request("projection repository mismatch"));
    }
    if projection.environment_id != request.environment_id {
        return Err(ApiError::bad_request("projection environment mismatch"));
    }
    let deploy_config = {
        let registry = state
            .registry
            .read()
            .map_err(|_| ApiError::internal("registry lock poisoned"))?;
        if let Some(service_id) = request.target.as_ref().map(|target| &target.service_id) {
            registry
                .deploy_configs
                .get(&(repository_id.clone(), service_id.clone()))
                .cloned()
        } else {
            let mut configs = registry
                .deploy_configs
                .iter()
                .filter(|((id, _), _)| *id == repository_id)
                .map(|(_, config)| config);
            let first = configs.next().cloned();
            if first.is_some() && configs.next().is_some() {
                return Err(ApiError::bad_request(
                    "this galaxy has deploy configs for multiple services; specify target.service_id",
                ));
            }
            first
        }
    };

    let target = if let Some(ref config) = deploy_config {
        Some(DeployTarget {
            provider_key: config.provider_key.clone(),
            service_id: config.service_id.clone(),
            environment_name: config.environment_name.clone(),
            context_path: config.context_path.clone(),
        })
    } else {
        request.target
    };

    let env_policy = deploy_config
        .as_ref()
        .and_then(|config| config.env_policy.clone())
        .or_else(|| {
            target.as_ref().map(|target| DeploymentEnvironmentPolicy {
                environment_name: target.environment_name.clone(),
                service_ids: vec![target.service_id.clone()],
                allow_build_variables: false,
                allow_runtime_variables: false,
                ..Default::default()
            })
        });
    let policy_evidence = deploy_policy_evidence(&projection, env_policy.clone())?;
    let release_gate_evidence = deploy_release_gate_evidence(
        state,
        &repository_id,
        request.release_gate_id.as_ref(),
        &request.environment_id,
        &request.requested_by,
    )?;
    let now = now_unix_ms();
    let mut intent = DeployIntent {
        schema_version: 1,
        id: DeployIntentId::generated(),
        repository_id: repository_id.clone(),
        projection_id: request.projection_id,
        snapshot_id: projection.snapshot_id,
        environment_id: request.environment_id,
        requested_provider_key: request.requested_provider_key,
        requested_by: request.requested_by,
        target,
        env_policy,
        policy_evidence: Some(policy_evidence),
        release_gate_evidence: Some(release_gate_evidence),
        trigger_source: request.trigger_source,
        state: DeployIntentState::Queued,
        astracollab_request_id: None,
        handoff: None,
        artifacts: Vec::new(),
        log_uri: None,
        error_message: None,
        attempts: 0,
        created_at_unix_ms: now,
        updated_at_unix_ms: now,
        completed_at_unix_ms: None,
    };
    let (archive_uri, archive_digest) =
        deploy_archive_artifact(state, &repository_id, &intent).await?;
    intent.artifacts.push(DeployArtifactRef {
        kind: "source_archive".to_string(),
        uri: archive_uri,
        digest: Some(format!("sha256:{archive_digest}")),
    });
    let handoff = sign_deploy_handoff(state, &intent)?;
    intent.astracollab_request_id = Some(handoff.request_id.clone());
    intent.handoff = Some(handoff.clone());
    intent.attempts = 1;
    intent.state = DeployIntentState::SentToAstracollab;
    intent.updated_at_unix_ms = now_unix_ms();
    let (deploy_url, deploy_secret) = if let Some(ref config) = deploy_config {
        (
            Some(config.deploy_url.clone()),
            Some(config.signing_secret.clone()),
        )
    } else {
        (
            state.astracollab_deploy_url.clone(),
            state.astracollab_deploy_signing_secret.clone(),
        )
    };

    if let Some(endpoint) = &deploy_url {
        let mut req = state.http_client.post(endpoint).json(&intent);
        if let Some(secret) = &deploy_secret {
            req = req.bearer_auth(secret);
        }
        let response = req.send().await.map_err(|error| {
            ApiError::internal(format!("astracollab deploy handoff failed: {error}"))
        })?;
        if !response.status().is_success() {
            return Err(ApiError {
                status: StatusCode::BAD_GATEWAY,
                message: format!("astracollab deploy handoff returned {}", response.status()),
            });
        }
    }
    persist_deploy_intent(state, &intent).await?;
    Ok(intent)
}

fn deploy_policy_evidence(
    projection: &Projection,
    env_policy: Option<DeploymentEnvironmentPolicy>,
) -> Result<DeployPolicyEvidence, ApiError> {
    let mut blocked_count = 0_u32;
    let mut embargo_count = 0_u32;
    let mut allowed_actions = Vec::new();

    for check in &projection.policy_checks {
        match check.decision {
            PolicyDecision::Allow => {
                push_policy_action(&mut allowed_actions, check.action.clone());
            }
            PolicyDecision::Embargo { .. } => {
                embargo_count += 1;
            }
            PolicyDecision::Block => {
                blocked_count += 1;
            }
            PolicyDecision::Redact | PolicyDecision::Template | PolicyDecision::Omit => {}
        }
    }

    if projection.policy_checks.is_empty() {
        return Err(ApiError::bad_request(
            "deploy projection is missing build-source policy evidence",
        ));
    }
    if blocked_count > 0 {
        return Err(ApiError::bad_request("deploy projection has blocked paths"));
    }
    if embargo_count > 0 {
        return Err(ApiError::bad_request(
            "deploy projection has embargoed paths",
        ));
    }

    let required_actions = vec![
        PolicyAction::ReadBuildSource,
        PolicyAction::CreateProjection,
        PolicyAction::Deploy,
    ];
    push_policy_action(&mut allowed_actions, PolicyAction::ReadBuildSource);
    push_policy_action(&mut allowed_actions, PolicyAction::CreateProjection);
    push_policy_action(&mut allowed_actions, PolicyAction::Deploy);

    Ok(DeployPolicyEvidence {
        required_actions,
        allowed_actions,
        blocked_count,
        embargo_count,
        manifest_digest: projection_policy_digest(projection)?,
        env_policy,
    })
}

fn push_policy_action(actions: &mut Vec<PolicyAction>, action: PolicyAction) {
    if !actions.contains(&action) {
        actions.push(action);
    }
}

fn projection_policy_digest(projection: &Projection) -> Result<String, ApiError> {
    let encoded = serde_json::to_vec(&projection.policy_checks).map_err(|error| {
        ApiError::internal(format!(
            "failed to encode projection policy evidence: {error}"
        ))
    })?;
    let mut hasher = Sha256::new();
    hasher.update(projection.repository_id.as_str().as_bytes());
    hasher.update(b":");
    hasher.update(projection.id.as_str().as_bytes());
    hasher.update(b":");
    hasher.update(projection.snapshot_id.as_str().as_bytes());
    hasher.update(b":");
    hasher.update(encoded);
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

fn deploy_release_gate_evidence(
    state: &AppState,
    repository_id: &RepositoryId,
    release_gate_id: Option<&ReleaseGateId>,
    environment_id: &EnvironmentId,
    requested_by: &Actor,
) -> Result<DeployReleaseGateEvidence, ApiError> {
    let Some(gate_id) = release_gate_id else {
        return Ok(DeployReleaseGateEvidence {
            gate_id: None,
            kind: None,
            decision: ReleaseGateDecision::Allow,
            reason: "no release gate configured".to_string(),
            effective_at_unix_ms: None,
        });
    };

    let gate = state
        .registry
        .read()
        .map_err(|_| ApiError::internal("registry lock poisoned"))?
        .release_gates
        .get(gate_id)
        .cloned()
        .ok_or_else(|| ApiError::not_found("release gate not found"))?;

    if &gate.repository_id != repository_id {
        return Err(ApiError::bad_request("release gate repository mismatch"));
    }
    if let Some(gate_environment_id) = &gate.environment_id
        && gate_environment_id != environment_id
    {
        return Err(ApiError::bad_request("release gate environment mismatch"));
    }
    if let Some(required_actor) = &gate.required_actor
        && required_actor != requested_by
    {
        return Err(ApiError::bad_request("release gate actor mismatch"));
    }

    let now = now_unix_ms();
    let (decision, effective_at_unix_ms) = match gate.kind {
        ReleaseGateKind::Immediate => (ReleaseGateDecision::Allow, None),
        ReleaseGateKind::DelayedUntil { unix_ms } if unix_ms <= now => {
            (ReleaseGateDecision::Allow, Some(unix_ms))
        }
        ReleaseGateKind::DelayedUntil { unix_ms } => (
            ReleaseGateDecision::Embargo {
                until_unix_ms: unix_ms,
            },
            Some(unix_ms),
        ),
        ReleaseGateKind::Embargoed => (ReleaseGateDecision::Block, None),
    };

    if !matches!(decision, ReleaseGateDecision::Allow) {
        return Err(ApiError::bad_request("release gate blocks deployment"));
    }

    Ok(DeployReleaseGateEvidence {
        gate_id: Some(gate.id),
        kind: Some(gate.kind),
        decision,
        reason: gate.reason,
        effective_at_unix_ms,
    })
}

async fn get_deploy_intent(
    State(state): State<AppState>,
    Path((repository_id, intent_id)): Path<(String, String)>,
) -> Result<Json<DeployIntentResponse>, ApiError> {
    let repository_id = RepositoryId::new(repository_id);
    ensure_repo(&state, &repository_id)?;
    let intent_id = DeployIntentId::new(intent_id);
    if let Some(intent) = durable_get_resource::<DeployIntent>(
        &state,
        Some(&repository_id),
        "deploy_intent",
        intent_id.as_str(),
    )
    .await?
    {
        return Ok(Json(DeployIntentResponse { intent }));
    }
    get_by_id(
        &state,
        |registry| {
            let intent = registry.deploy_intents.get(&intent_id)?;
            (intent.repository_id == repository_id).then(|| DeployIntentResponse {
                intent: intent.clone(),
            })
        },
        "deploy intent not found",
    )
}

async fn update_deploy_intent_status(
    State(state): State<AppState>,
    Path((repository_id, intent_id)): Path<(String, String)>,
    Json(request): Json<DeployStatusCallbackRequest>,
) -> Result<Json<DeployIntentResponse>, ApiError> {
    let repository_id = RepositoryId::new(repository_id);
    ensure_repo(&state, &repository_id)?;
    let intent_id = DeployIntentId::new(intent_id);
    let mut intent = if let Some(intent) = durable_get_resource::<DeployIntent>(
        &state,
        Some(&repository_id),
        "deploy_intent",
        intent_id.as_str(),
    )
    .await?
    {
        intent
    } else {
        state
            .registry
            .read()
            .map_err(|_| ApiError::internal("registry lock poisoned"))?
            .deploy_intents
            .get(&intent_id)
            .cloned()
            .ok_or_else(|| ApiError::not_found("deploy intent not found"))?
    };
    if intent.repository_id != repository_id {
        return Err(ApiError::bad_request("deploy intent repository mismatch"));
    }
    if !valid_deploy_status_transition(&intent.state, &request.state) {
        return Err(ApiError::bad_request(
            "invalid deploy intent state transition",
        ));
    }
    intent.state = request.state;
    intent.artifacts = request.artifacts;
    intent.log_uri = request.log_uri;
    intent.error_message = request.error_message;
    intent.updated_at_unix_ms = now_unix_ms();
    if matches!(
        intent.state,
        DeployIntentState::Succeeded | DeployIntentState::Failed | DeployIntentState::Cancelled
    ) {
        intent.completed_at_unix_ms = Some(intent.updated_at_unix_ms);
    }
    persist_deploy_intent(&state, &intent).await?;
    Ok(Json(DeployIntentResponse { intent }))
}

fn valid_deploy_status_transition(current: &DeployIntentState, next: &DeployIntentState) -> bool {
    use DeployIntentState::*;
    matches!(
        (current, next),
        (Queued, SentToAstracollab | Running | Failed | Cancelled)
            | (SentToAstracollab, Running | Succeeded | Failed | Cancelled)
            | (Running, Running | Succeeded | Failed | Cancelled)
            | (Succeeded, Succeeded)
            | (Failed, Failed)
            | (Cancelled, Cancelled)
    )
}

async fn put_auth_token(
    State(state): State<AppState>,
    Path(repository_id): Path<String>,
    Json(request): Json<CreateAuthTokenRequest>,
) -> Result<Json<CreateAuthTokenResponse>, ApiError> {
    let repository_id = RepositoryId::new(repository_id);
    ensure_repo(&state, &repository_id)?;
    if state.external_auth_provider.is_some() {
        return Err(ApiError::bad_request(
            "Better Auth RS owns API-key creation and revocation; use /auth/api-key/create",
        ));
    }
    if matches!(
        state.auth.token_authority,
        AuthTokenAuthority::AstracollabHosted
    ) {
        return Err(ApiError::bad_request(
            "hosted Nebula uses external auth provider API keys; registry token writes are disabled",
        ));
    }
    let response = create_server_auth_token(repository_id.clone(), request)?;
    durable_put_resource(
        &state,
        Some(&repository_id),
        "auth_token",
        response.token.id.as_str(),
        &response.token,
    )
    .await?;
    state
        .registry
        .write()
        .map_err(|_| ApiError::internal("registry lock poisoned"))?
        .auth_tokens
        .insert(response.token.id.clone(), response.token.clone());
    persist_state(&state).await?;
    Ok(Json(response))
}

async fn put_proposal_comment(
    State(state): State<AppState>,
    Path(repository_id): Path<String>,
    Json(comment): Json<ProposalComment>,
) -> Result<Json<ProposalComment>, ApiError> {
    ensure_repo_match(
        &state,
        &RepositoryId::new(repository_id),
        &comment.repository_id,
    )?;
    durable_put_resource(
        &state,
        Some(&comment.repository_id),
        "proposal_comment",
        comment.id.as_str(),
        &comment,
    )
    .await?;
    state
        .registry
        .write()
        .map_err(|_| ApiError::internal("registry lock poisoned"))?
        .proposal_comments
        .insert(comment.id.clone(), comment.clone());
    persist_state(&state).await?;
    Ok(Json(comment))
}

async fn put_proposal_check(
    State(state): State<AppState>,
    Path(repository_id): Path<String>,
    Json(check): Json<ProposalStatusCheck>,
) -> Result<Json<ProposalStatusCheck>, ApiError> {
    ensure_repo_match(
        &state,
        &RepositoryId::new(repository_id),
        &check.repository_id,
    )?;
    durable_put_resource(
        &state,
        Some(&check.repository_id),
        "proposal_check",
        check.id.as_str(),
        &check,
    )
    .await?;
    state
        .registry
        .write()
        .map_err(|_| ApiError::internal("registry lock poisoned"))?
        .proposal_checks
        .insert(check.id.clone(), check.clone());
    persist_state(&state).await?;
    Ok(Json(check))
}

async fn put_webhook_endpoint(
    State(state): State<AppState>,
    Path(repository_id): Path<String>,
    Json(endpoint): Json<WebhookEndpoint>,
) -> Result<Json<WebhookEndpoint>, ApiError> {
    let repository_id = RepositoryId::new(repository_id);
    ensure_repo(&state, &repository_id)?;
    if endpoint
        .repository_id
        .as_ref()
        .is_some_and(|id| id != &repository_id)
    {
        return Err(ApiError::bad_request(
            "webhook endpoint repository mismatch",
        ));
    }
    durable_put_resource(
        &state,
        endpoint.repository_id.as_ref().or(Some(&repository_id)),
        "webhook_endpoint",
        endpoint.id.as_str(),
        &endpoint,
    )
    .await?;
    state
        .registry
        .write()
        .map_err(|_| ApiError::internal("registry lock poisoned"))?
        .webhook_endpoints
        .insert(endpoint.id.clone(), endpoint.clone());
    persist_state(&state).await?;
    Ok(Json(endpoint))
}

async fn put_webhook_event(
    State(state): State<AppState>,
    Path(repository_id): Path<String>,
    Json(event): Json<WebhookEvent>,
) -> Result<Json<WebhookEvent>, ApiError> {
    ensure_repo_match(
        &state,
        &RepositoryId::new(repository_id),
        &event.repository_id,
    )?;
    durable_put_resource(
        &state,
        Some(&event.repository_id),
        "webhook_event",
        event.id.as_str(),
        &event,
    )
    .await?;
    state
        .registry
        .write()
        .map_err(|_| ApiError::internal("registry lock poisoned"))?
        .webhook_events
        .insert(event.id.clone(), event.clone());
    persist_state(&state).await?;
    Ok(Json(event))
}

async fn put_sync_session(
    State(state): State<AppState>,
    Path(repository_id): Path<String>,
    Json(session): Json<SyncSession>,
) -> Result<Json<SyncSession>, ApiError> {
    ensure_repo_match(
        &state,
        &RepositoryId::new(repository_id),
        &session.repository_id,
    )?;
    durable_put_resource(
        &state,
        Some(&session.repository_id),
        "sync_session",
        session.id.as_str(),
        &session,
    )
    .await?;
    state
        .registry
        .write()
        .map_err(|_| ApiError::internal("registry lock poisoned"))?
        .sync_sessions
        .insert(session.id.clone(), session.clone());
    persist_state(&state).await?;
    emit_telemetry_event(
        state.clone(),
        telemetry_event(
            "sync.session.started",
            TelemetrySource::Sync,
            TelemetrySeverity::Info,
            "sync session started",
            NebulaTelemetryContext {
                repository_id: Some(session.repository_id.clone()),
                sync_session_id: Some(session.id.clone()),
                ..Default::default()
            },
            BTreeMap::new(),
        ),
    );
    Ok(Json(session))
}

async fn start_sync_session(
    State(state): State<AppState>,
    Path(repository_id): Path<String>,
    Json(request): Json<StartSyncSessionRequest>,
) -> Result<Json<SyncSession>, ApiError> {
    let repository_id = RepositoryId::new(repository_id);
    ensure_repo(&state, &repository_id)?;
    cleanup_expired_sync_sessions(&state).await?;
    let lease_expires_at_unix_ms = now_unix_ms() + 15 * 60 * 1000;
    let session = SyncSession {
        id: SyncSessionId::generated(),
        repository_id: repository_id.clone(),
        actor: request.actor,
        base_snapshot_id: None,
        target_ref: request.base_ref,
        state: SyncSessionState::Open,
        lease_expires_at_unix_ms,
        uploaded_blob_count: 0,
        downloaded_blob_count: 0,
        operation_id: None,
    };
    durable_put_resource(
        &state,
        Some(&repository_id),
        "sync_session",
        session.id.as_str(),
        &session,
    )
    .await?;
    state
        .registry
        .write()
        .map_err(|_| ApiError::internal("registry lock poisoned"))?
        .sync_sessions
        .insert(session.id.clone(), session.clone());
    persist_state(&state).await?;
    Ok(Json(session))
}

async fn get_sync_session(
    State(state): State<AppState>,
    Path((repository_id, session_id)): Path<(String, String)>,
) -> Result<Json<SyncSession>, ApiError> {
    let repository_id = RepositoryId::new(repository_id);
    ensure_repo(&state, &repository_id)?;
    if let Some(session) =
        durable_get_resource(&state, Some(&repository_id), "sync_session", &session_id).await?
    {
        return Ok(Json(session));
    }
    get_by_id(
        &state,
        |registry| {
            let session = registry
                .sync_sessions
                .get(&SyncSessionId::new(session_id))?;
            (session.repository_id == repository_id).then(|| session.clone())
        },
        "sync session not found",
    )
}

async fn put_sync_session_chunks(
    State(state): State<AppState>,
    Path((repository_id, session_id)): Path<(String, String)>,
    Json(manifest): Json<ChunkTransferManifest>,
) -> Result<Json<ChunkTransferManifest>, ApiError> {
    let repository_id = RepositoryId::new(repository_id);
    let session_id = SyncSessionId::new(session_id);
    ensure_open_sync_session(&state, &repository_id, &session_id).await?;
    if manifest.repository_id != repository_id || manifest.session_id != session_id {
        return Err(ApiError::bad_request("chunk manifest route mismatch"));
    }
    durable_put_resource(
        &state,
        Some(&repository_id),
        "chunk_manifest",
        manifest.session_id.as_str(),
        &manifest,
    )
    .await?;
    state
        .registry
        .write()
        .map_err(|_| ApiError::internal("registry lock poisoned"))?
        .chunk_manifests
        .insert(session_id, manifest.clone());
    persist_state(&state).await?;
    Ok(Json(manifest))
}

async fn put_sync_session_bundle(
    State(state): State<AppState>,
    Path((repository_id, session_id)): Path<(String, String)>,
    Json(bundle): Json<RegistrySyncBundle>,
) -> Result<Json<RegistrySyncBundle>, ApiError> {
    let repository_id = RepositoryId::new(repository_id);
    let session_id = SyncSessionId::new(session_id);
    ensure_open_sync_session(&state, &repository_id, &session_id).await?;
    if bundle.repository_id != repository_id {
        return Err(ApiError::bad_request("sync bundle repository mismatch"));
    }
    durable_put_resource(
        &state,
        Some(&repository_id),
        "sync_bundle",
        session_id.as_str(),
        &bundle,
    )
    .await?;
    state
        .registry
        .write()
        .map_err(|_| ApiError::internal("registry lock poisoned"))?
        .sync_bundles
        .insert(session_id, bundle.clone());
    persist_state(&state).await?;
    Ok(Json(bundle))
}

async fn put_sync_session_chunk(
    State(state): State<AppState>,
    Path((repository_id, session_id, chunk_id)): Path<(String, String, String)>,
    Json(request): Json<SyncChunkUploadRequest>,
) -> Result<Json<SyncChunkRecord>, ApiError> {
    let repository_id = RepositoryId::new(repository_id);
    let session_id = SyncSessionId::new(session_id);
    let chunk_id = BlobChunkId::new(chunk_id);
    ensure_open_sync_session(&state, &repository_id, &session_id).await?;
    if request.chunk.id != chunk_id {
        return Err(ApiError::bad_request("chunk route mismatch"));
    }
    let bytes = request.bytes;
    let computed = BlobChunk::from_bytes(request.chunk.offset, &bytes);
    if computed.hash != request.chunk.hash || computed.size_bytes != request.chunk.size_bytes {
        return Err(ApiError::bad_request("chunk checksum mismatch"));
    }
    let record = SyncChunkRecord {
        repository_id: repository_id.clone(),
        session_id: session_id.clone(),
        chunk: request.chunk,
        bytes,
    };
    durable_put_resource(
        &state,
        Some(&repository_id),
        "sync_chunk",
        &format!("{}_{}", session_id, chunk_id),
        &record,
    )
    .await?;
    let updated_session = {
        let mut registry = state
            .registry
            .write()
            .map_err(|_| ApiError::internal("registry lock poisoned"))?;
        registry
            .sync_chunks
            .insert((session_id.clone(), chunk_id), record.clone());
        let uploaded_blob_count = registry
            .sync_chunks
            .keys()
            .filter(|(id, _)| id == &session_id)
            .count() as u64;
        let mut updated = None;
        if let Some(session) = registry.sync_sessions.get_mut(&session_id) {
            session.state = SyncSessionState::Uploading;
            session.uploaded_blob_count = uploaded_blob_count;
            updated = Some(session.clone());
        }
        updated
    };
    if let Some(session) = &updated_session {
        persist_sync_session_state(&state, session).await?;
    }
    persist_state(&state).await?;
    Ok(Json(record))
}

async fn get_sync_session_chunk(
    State(state): State<AppState>,
    Path((repository_id, session_id, chunk_id)): Path<(String, String, String)>,
) -> Result<Json<SyncChunkRecord>, ApiError> {
    let repository_id = RepositoryId::new(repository_id);
    ensure_repo(&state, &repository_id)?;
    let session_id = SyncSessionId::new(session_id);
    let chunk_id = BlobChunkId::new(chunk_id);
    if let Some(record) = durable_get_resource::<SyncChunkRecord>(
        &state,
        Some(&repository_id),
        "sync_chunk",
        &format!("{}_{}", session_id, chunk_id),
    )
    .await?
    {
        return Ok(Json(record));
    }
    get_by_id(
        &state,
        |registry| {
            let record = registry.sync_chunks.get(&(session_id, chunk_id))?;
            (record.repository_id == repository_id).then(|| record.clone())
        },
        "sync chunk not found",
    )
}

async fn get_missing_sync_session_blobs(
    State(state): State<AppState>,
    Path((repository_id, session_id)): Path<(String, String)>,
    Json(request): Json<BlobPresenceRequest>,
) -> Result<Json<BlobPresenceResponse>, ApiError> {
    let repository_id = RepositoryId::new(repository_id);
    let session_id = SyncSessionId::new(session_id);
    ensure_open_sync_session(&state, &repository_id, &session_id).await?;
    let mut present = Vec::new();
    let mut missing = Vec::new();
    let mut checks = stream::iter(request.blobs.into_iter().map(|blob| {
        let state = state.clone();
        let repository_id = repository_id.clone();
        let session_id = session_id.clone();
        async move {
            let is_present =
                sync_blob_is_present(&state, &repository_id, &session_id, &blob).await?;
            Ok::<_, ApiError>((blob, is_present))
        }
    }))
    .buffer_unordered(16);
    while let Some(result) = checks.next().await {
        let (blob, is_present) = result?;
        if is_present {
            record_ephemeral_staged_blob_upload(&state, &repository_id, &session_id, blob.clone())?;
            present.push(blob.hash);
        } else {
            missing.push(blob);
        }
    }
    Ok(Json(BlobPresenceResponse { present, missing }))
}

async fn plan_sync_session_blob_uploads(
    State(state): State<AppState>,
    Path((repository_id, session_id)): Path<(String, String)>,
    Json(request): Json<BlobUploadBatchRequest>,
) -> Result<Json<BlobUploadBatchResponse>, ApiError> {
    let repository_id = RepositoryId::new(repository_id);
    let session_id = SyncSessionId::new(session_id);
    ensure_open_sync_session(&state, &repository_id, &session_id).await?;
    let mut present = Vec::new();
    let mut uploads = Vec::new();
    let recorded_present = {
        let registry = state
            .registry
            .read()
            .map_err(|_| ApiError::internal("registry lock poisoned"))?;
        request
            .blobs
            .iter()
            .filter(|blob| {
                let blob_id = BlobId::from_hash(&blob.hash);
                registry
                    .staged_blob_uploads
                    .get(&(session_id.clone(), blob_id))
                    .map(|upload| upload.state == StagedBlobState::Uploaded)
                    .unwrap_or(false)
                    || registry.blobs.contains_key(&blob.hash)
            })
            .map(|blob| blob.hash.clone())
            .collect::<BTreeSet<_>>()
    };
    for blob in request.blobs {
        let is_present = recorded_present.contains(&blob.hash);
        if is_present {
            record_ephemeral_staged_blob_upload(&state, &repository_id, &session_id, blob.clone())?;
            present.push(blob.hash);
            continue;
        }
        let transfer = if let Some(store) = &state.object_blob_store {
            match store
                .signed_put_url(
                    &blob.hash,
                    Duration::from_secs(DIRECT_UPLOAD_URL_TTL_SECONDS),
                )
                .await
                .map_err(storage_api_error)?
            {
                Some(url) => BlobUploadTransfer::DirectPut {
                    url,
                    headers: BTreeMap::new(),
                    expires_at_unix_ms: now_unix_ms() + (DIRECT_UPLOAD_URL_TTL_SECONDS * 1_000),
                },
                None => BlobUploadTransfer::RegistryPut,
            }
        } else {
            BlobUploadTransfer::RegistryPut
        };
        uploads.push(BlobUploadAction { blob, transfer });
    }
    Ok(Json(BlobUploadBatchResponse { present, uploads }))
}

async fn confirm_sync_session_blob_uploads(
    State(state): State<AppState>,
    Path((repository_id, session_id)): Path<(String, String)>,
    Json(request): Json<BlobUploadConfirmRequest>,
) -> Result<Json<BlobUploadConfirmResponse>, ApiError> {
    let repository_id = RepositoryId::new(repository_id);
    let session_id = SyncSessionId::new(session_id);
    ensure_open_sync_session(&state, &repository_id, &session_id).await?;
    let Some(store) = &state.object_blob_store else {
        return Err(ApiError::bad_request(
            "direct upload confirmation requires an object blob store",
        ));
    };
    let mut uploaded = Vec::new();
    let mut confirmations = stream::iter(request.blobs.into_iter().map(|blob| {
        let store = store.clone();
        async move {
            let size = store
                .object_size(&blob.hash)
                .await
                .map_err(storage_api_error)?
                .ok_or_else(|| {
                    ApiError::bad_request(format!(
                        "direct-uploaded blob {} is missing",
                        blob.hash.digest
                    ))
                })?;
            Ok::<_, ApiError>((blob, size))
        }
    }))
    .buffer_unordered(64);
    while let Some(result) = confirmations.next().await {
        let (blob, size) = result?;
        if size != blob.size_bytes {
            return Err(ApiError::bad_request(format!(
                "direct-uploaded blob {} has size {}, expected {}",
                blob.hash.digest, size, blob.size_bytes
            )));
        }
        let upload =
            record_ephemeral_staged_blob_upload(&state, &repository_id, &session_id, blob.clone())?;
        uploaded.push(upload.blob.hash);
    }
    Ok(Json(BlobUploadConfirmResponse { uploaded }))
}

async fn put_sync_session_blob_pack(
    State(state): State<AppState>,
    Path((repository_id, session_id)): Path<(String, String)>,
    Json(request): Json<BlobPackUploadRequest>,
) -> Result<Json<BlobPackUploadResponse>, ApiError> {
    let repository_id = RepositoryId::new(repository_id);
    let session_id = SyncSessionId::new(session_id);
    ensure_open_sync_session(&state, &repository_id, &session_id).await?;
    let Some(blob_store) = &state.blob_store else {
        return Err(ApiError::bad_request(
            "streaming sync requires a configured blob store",
        ));
    };
    let mut uploaded = Vec::new();
    let mut uploads = stream::iter(request.blobs.into_iter().map(|entry| {
        let blob_store = blob_store.clone();
        async move {
            let computed = ContentHash::sha256(&entry.bytes);
            if computed != entry.blob.hash || entry.blob.size_bytes != entry.bytes.len() as u64 {
                return Err(ApiError::bad_request("packed blob checksum mismatch"));
            }
            blob_store
                .put(&entry.blob.hash, &entry.bytes)
                .await
                .map_err(storage_api_error)?;
            Ok::<_, ApiError>(entry.blob)
        }
    }))
    .buffer_unordered(16);
    while let Some(result) = uploads.next().await {
        let blob = result?;
        record_staged_blob_upload(&state, &repository_id, &session_id, blob.clone()).await?;
        uploaded.push(blob.hash);
    }
    Ok(Json(BlobPackUploadResponse { uploaded }))
}

async fn put_sync_session_blob(
    State(state): State<AppState>,
    Path((repository_id, session_id, algorithm, digest)): Path<(String, String, String, String)>,
    body: Body,
) -> Result<Json<StagedBlobUpload>, ApiError> {
    let repository_id = RepositoryId::new(repository_id);
    let session_id = SyncSessionId::new(session_id);
    ensure_open_sync_session(&state, &repository_id, &session_id).await?;
    let hash = ContentHash { algorithm, digest };
    let Some(blob_store) = &state.blob_store else {
        return Err(ApiError::bad_request(
            "streaming sync requires a configured blob store",
        ));
    };
    let stream = body.into_data_stream().map(|chunk| {
        chunk.map_err(|error| NebulaError::InvalidOperation(format!("invalid body: {error}")))
    });
    let size_bytes = blob_store
        .put_stream(&hash, Box::pin(stream))
        .await
        .map_err(storage_api_error)?;
    let blob = ContentBlob {
        id: BlobId::from_hash(&hash),
        hash: hash.clone(),
        size_bytes,
        media_type: None,
        visibility: BlobVisibility::Public,
    };
    let upload = record_staged_blob_upload(&state, &repository_id, &session_id, blob).await?;
    let mut attributes = BTreeMap::new();
    attributes.insert("blob_hash".to_string(), json!(hash));
    attributes.insert("received_bytes".to_string(), json!(size_bytes));
    emit_telemetry_event(
        state.clone(),
        telemetry_event(
            "sync.blob.uploaded",
            TelemetrySource::BlobStore,
            TelemetrySeverity::Info,
            "streamed blob uploaded",
            NebulaTelemetryContext {
                repository_id: Some(repository_id),
                sync_session_id: Some(session_id),
                ..Default::default()
            },
            attributes,
        ),
    );
    Ok(Json(upload))
}

async fn sync_blob_is_present(
    state: &AppState,
    repository_id: &RepositoryId,
    session_id: &SyncSessionId,
    blob: &ContentBlob,
) -> Result<bool, ApiError> {
    let blob_id = BlobId::from_hash(&blob.hash);
    let present_in_session = state
        .registry
        .read()
        .map_err(|_| ApiError::internal("registry lock poisoned"))?
        .staged_blob_uploads
        .get(&(session_id.clone(), blob_id.clone()))
        .map(|upload| upload.state == StagedBlobState::Uploaded)
        .unwrap_or(false);
    if present_in_session {
        return Ok(true);
    }
    if durable_get_resource::<StagedBlobUpload>(
        state,
        Some(repository_id),
        "staged_blob_upload",
        &format!("{}_{}", session_id, blob_id),
    )
    .await?
    .map(|upload| upload.state == StagedBlobState::Uploaded)
    .unwrap_or(false)
    {
        return Ok(true);
    }
    let present_in_registry = state
        .registry
        .read()
        .map_err(|_| ApiError::internal("registry lock poisoned"))?
        .blobs
        .contains_key(&blob.hash);
    if present_in_registry {
        return Ok(true);
    }
    let Some(blob_store) = &state.blob_store else {
        return Ok(false);
    };
    blob_store
        .exists(&blob.hash)
        .await
        .map_err(storage_api_error)
}

async fn record_staged_blob_upload(
    state: &AppState,
    repository_id: &RepositoryId,
    session_id: &SyncSessionId,
    blob: ContentBlob,
) -> Result<StagedBlobUpload, ApiError> {
    let now = now_unix_ms();
    let upload = StagedBlobUpload {
        repository_id: repository_id.clone(),
        session_id: session_id.clone(),
        received_bytes: blob.size_bytes,
        blob: blob.clone(),
        state: StagedBlobState::Uploaded,
        created_at_unix_ms: now,
        updated_at_unix_ms: now,
    };
    durable_put_resource(
        state,
        Some(repository_id),
        "staged_blob_upload",
        &format!("{}_{}", session_id, BlobId::from_hash(&blob.hash)),
        &upload,
    )
    .await?;
    let updated_session = {
        let mut registry = state
            .registry
            .write()
            .map_err(|_| ApiError::internal("registry lock poisoned"))?;
        registry.staged_blob_uploads.insert(
            (session_id.clone(), BlobId::from_hash(&blob.hash)),
            upload.clone(),
        );
        let uploaded_blob_count = registry
            .staged_blob_uploads
            .keys()
            .filter(|(id, _)| id == session_id)
            .count() as u64;
        if let Some(session) = registry.sync_sessions.get_mut(session_id) {
            session.state = SyncSessionState::Uploading;
            session.uploaded_blob_count = uploaded_blob_count;
            Some(session.clone())
        } else {
            None
        }
    };
    if let Some(session) = &updated_session {
        persist_sync_session_state(state, session).await?;
    }
    Ok(upload)
}

fn record_ephemeral_staged_blob_upload(
    state: &AppState,
    repository_id: &RepositoryId,
    session_id: &SyncSessionId,
    blob: ContentBlob,
) -> Result<StagedBlobUpload, ApiError> {
    let now = now_unix_ms();
    let upload = StagedBlobUpload {
        repository_id: repository_id.clone(),
        session_id: session_id.clone(),
        received_bytes: blob.size_bytes,
        blob: blob.clone(),
        state: StagedBlobState::Uploaded,
        created_at_unix_ms: now,
        updated_at_unix_ms: now,
    };
    let mut registry = state
        .registry
        .write()
        .map_err(|_| ApiError::internal("registry lock poisoned"))?;
    registry.staged_blob_uploads.insert(
        (session_id.clone(), BlobId::from_hash(&blob.hash)),
        upload.clone(),
    );
    let uploaded_blob_count = registry
        .staged_blob_uploads
        .keys()
        .filter(|(id, _)| id == session_id)
        .count() as u64;
    if let Some(session) = registry.sync_sessions.get_mut(session_id) {
        session.state = SyncSessionState::Uploading;
        session.uploaded_blob_count = uploaded_blob_count;
    }
    Ok(upload)
}

async fn get_sync_session_blob(
    State(state): State<AppState>,
    Path((repository_id, session_id, algorithm, digest)): Path<(String, String, String, String)>,
) -> Result<Response, ApiError> {
    let repository_id = RepositoryId::new(repository_id);
    ensure_repo(&state, &repository_id)?;
    let session_id = SyncSessionId::new(session_id);
    let hash = ContentHash { algorithm, digest };
    let Some(blob_store) = &state.blob_store else {
        return Err(ApiError::bad_request(
            "streaming sync requires a configured blob store",
        ));
    };
    let tmp_path = sync_temp_path(&session_id, &hash);
    blob_store
        .get_to_path(&hash, &tmp_path)
        .await
        .map_err(storage_api_error)?;
    let file = tokio::fs::File::open(&tmp_path)
        .await
        .map_err(|error| ApiError::internal(format!("failed to open staged download: {error}")))?;
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/octet-stream")
        .body(Body::from_stream(ReaderStream::new(file)))
        .map_err(|error| ApiError::internal(format!("failed to build response: {error}")))
}

async fn validate_sync_session(
    State(state): State<AppState>,
    Path((repository_id, session_id)): Path<(String, String)>,
) -> Result<Json<SyncSessionValidation>, ApiError> {
    let repository_id = RepositoryId::new(repository_id);
    let session_id = SyncSessionId::new(session_id);
    ensure_open_sync_session(&state, &repository_id, &session_id).await?;
    let manifest = {
        let memory_manifest = state
            .registry
            .read()
            .map_err(|_| ApiError::internal("registry lock poisoned"))?
            .chunk_manifests
            .get(&session_id)
            .cloned();
        if let Some(manifest) = memory_manifest {
            manifest
        } else {
            durable_get_resource::<ChunkTransferManifest>(
                &state,
                Some(&repository_id),
                "chunk_manifest",
                session_id.as_str(),
            )
            .await?
            .ok_or_else(|| ApiError::bad_request("sync session has no chunk manifest"))?
        }
    };
    struct PendingChunk {
        chunk_id: BlobChunkId,
        chunk_durable_id: String,
        blob_durable_id: Option<String>,
        blob_present_in_memory: bool,
    }
    let mut pending = Vec::with_capacity(manifest.chunks.len());
    let mut chunk_durable_ids = Vec::new();
    let mut blob_durable_ids = Vec::new();
    {
        let registry = state
            .registry
            .read()
            .map_err(|_| ApiError::internal("registry lock poisoned"))?;
        for chunk in &manifest.chunks {
            let chunk_id = BlobChunkId::from_hash(&chunk.hash);
            if registry
                .sync_chunks
                .contains_key(&(session_id.clone(), chunk_id.clone()))
            {
                continue;
            }
            let chunk_durable_id = format!("{}_{}", session_id, chunk_id);
            let (blob_durable_id, blob_present_in_memory) =
                if let Some(blob_hash) = &chunk.blob_hash {
                    let blob_id = BlobId::from_hash(blob_hash);
                    let present_in_memory = registry
                        .staged_blob_uploads
                        .get(&(session_id.clone(), blob_id.clone()))
                        .map(|upload| upload.state == StagedBlobState::Uploaded)
                        .unwrap_or(false);
                    let durable_id = format!("{}_{}", session_id, blob_id);
                    (Some(durable_id), present_in_memory)
                } else {
                    (None, false)
                };
            chunk_durable_ids.push(chunk_durable_id.clone());
            if let Some(durable_id) = &blob_durable_id
                && !blob_present_in_memory
            {
                blob_durable_ids.push(durable_id.clone());
            }
            pending.push(PendingChunk {
                chunk_id,
                chunk_durable_id,
                blob_durable_id,
                blob_present_in_memory,
            });
        }
    }
    let durable_chunks: BTreeSet<String> = durable_get_resources_batch::<SyncChunkRecord>(
        &state,
        Some(&repository_id),
        "sync_chunk",
        &chunk_durable_ids,
    )
    .await?
    .into_iter()
    .map(|(id, _)| id)
    .collect();
    let durable_uploaded_blobs: BTreeSet<String> = durable_get_resources_batch::<StagedBlobUpload>(
        &state,
        Some(&repository_id),
        "staged_blob_upload",
        &blob_durable_ids,
    )
    .await?
    .into_iter()
    .filter(|(_, upload)| upload.state == StagedBlobState::Uploaded)
    .map(|(id, _)| id)
    .collect();
    let mut missing_chunks = Vec::new();
    for chunk in pending {
        let present_durable_chunk = durable_chunks.contains(&chunk.chunk_durable_id);
        let present_durable_blob = chunk.blob_present_in_memory
            || chunk
                .blob_durable_id
                .as_ref()
                .is_some_and(|id| durable_uploaded_blobs.contains(id));
        if !present_durable_chunk && !present_durable_blob {
            missing_chunks.push(chunk.chunk_id);
        }
    }
    let valid = missing_chunks.is_empty();
    if valid {
        let updated_session = {
            let mut registry = state
                .registry
                .write()
                .map_err(|_| ApiError::internal("registry lock poisoned"))?;
            let Some(session) = registry.sync_sessions.get_mut(&session_id) else {
                return Err(ApiError::not_found("sync session not found"));
            };
            session.state = SyncSessionState::Validated;
            session.clone()
        };
        persist_sync_session_state(&state, &updated_session).await?;
        persist_state(&state).await?;
    }
    let mut attributes = BTreeMap::new();
    attributes.insert("valid".to_string(), json!(valid));
    attributes.insert(
        "missing_chunk_count".to_string(),
        json!(missing_chunks.len()),
    );
    emit_telemetry_event(
        state.clone(),
        telemetry_event(
            "sync.session.validated",
            TelemetrySource::Sync,
            if valid {
                TelemetrySeverity::Info
            } else {
                TelemetrySeverity::Warning
            },
            "sync session validation completed",
            NebulaTelemetryContext {
                repository_id: Some(repository_id),
                sync_session_id: Some(session_id.clone()),
                ..Default::default()
            },
            attributes,
        ),
    );
    Ok(Json(SyncSessionValidation {
        session_id,
        valid,
        missing_chunks,
    }))
}

async fn commit_sync_session(
    State(state): State<AppState>,
    Path((repository_id, session_id)): Path<(String, String)>,
) -> Result<Json<SyncSession>, ApiError> {
    let repository_id = RepositoryId::new(repository_id);
    let session_id = SyncSessionId::new(session_id);
    let validation = validate_sync_session(
        State(state.clone()),
        Path((
            repository_id.as_str().to_string(),
            session_id.as_str().to_string(),
        )),
    )
    .await?
    .0;
    if !validation.valid {
        return Err(ApiError::bad_request("sync session has missing chunks"));
    }
    let bundle = {
        let (memory_bundle, memory_manifest, memory_chunks_by_hash, staged_blob_hashes) = {
            let registry = state
                .registry
                .read()
                .map_err(|_| ApiError::internal("registry lock poisoned"))?;
            let chunks_by_hash = registry
                .sync_chunks
                .iter()
                .filter(|((record_session_id, _), _)| record_session_id == &session_id)
                .map(|(_, record)| (record.chunk.hash.clone(), record.bytes.clone()))
                .collect::<BTreeMap<_, _>>();
            let staged_blob_hashes = registry
                .staged_blob_uploads
                .iter()
                .filter(|((record_session_id, _), upload)| {
                    record_session_id == &session_id && upload.state == StagedBlobState::Uploaded
                })
                .map(|(_, upload)| upload.blob.hash.clone())
                .collect::<BTreeSet<_>>();
            (
                registry.sync_bundles.get(&session_id).cloned(),
                registry.chunk_manifests.get(&session_id).cloned(),
                chunks_by_hash,
                staged_blob_hashes,
            )
        };
        let mut bundle = if let Some(bundle) = memory_bundle {
            bundle
        } else {
            durable_get_resource::<RegistrySyncBundle>(
                &state,
                Some(&repository_id),
                "sync_bundle",
                session_id.as_str(),
            )
            .await?
            .ok_or_else(|| ApiError::bad_request("sync session has no metadata bundle"))?
        };
        let manifest = if let Some(manifest) = memory_manifest {
            manifest
        } else {
            durable_get_resource::<ChunkTransferManifest>(
                &state,
                Some(&repository_id),
                "chunk_manifest",
                session_id.as_str(),
            )
            .await?
            .ok_or_else(|| ApiError::bad_request("sync session has no chunk manifest"))?
        };
        let mut chunks_by_hash = memory_chunks_by_hash;
        let needed_chunk_durable_ids = manifest
            .chunks
            .iter()
            .filter(|descriptor| {
                !chunks_by_hash.contains_key(&descriptor.hash)
                    && !descriptor
                        .blob_hash
                        .as_ref()
                        .map(|hash| staged_blob_hashes.contains(hash))
                        .unwrap_or(false)
            })
            .map(|descriptor| {
                format!(
                    "{}_{}",
                    session_id,
                    BlobChunkId::from_hash(&descriptor.hash)
                )
            })
            .collect::<Vec<_>>();
        for (_, record) in durable_get_resources_batch::<SyncChunkRecord>(
            &state,
            Some(&repository_id),
            "sync_chunk",
            &needed_chunk_durable_ids,
        )
        .await?
        {
            chunks_by_hash.insert(record.chunk.hash.clone(), record.bytes);
        }
        let needed_blob_durable_ids = {
            let registry = state
                .registry
                .read()
                .map_err(|_| ApiError::internal("registry lock poisoned"))?;
            bundle
                .blobs
                .iter()
                .filter(|blob| {
                    blob.bytes.is_empty()
                        && !registry
                            .staged_blob_uploads
                            .contains_key(&(session_id.clone(), blob.blob.id.clone()))
                })
                .map(|blob| format!("{}_{}", session_id, blob.blob.id))
                .collect::<Vec<_>>()
        };
        let mut durable_staged_uploads: BTreeMap<String, StagedBlobUpload> =
            durable_get_resources_batch::<StagedBlobUpload>(
                &state,
                Some(&repository_id),
                "staged_blob_upload",
                &needed_blob_durable_ids,
            )
            .await?
            .into_iter()
            .collect();
        for blob in &mut bundle.blobs {
            if blob.bytes.is_empty() {
                let memory_upload = state
                    .registry
                    .read()
                    .map_err(|_| ApiError::internal("registry lock poisoned"))?
                    .staged_blob_uploads
                    .get(&(session_id.clone(), blob.blob.id.clone()))
                    .cloned();
                let staged_upload = if let Some(upload) = memory_upload {
                    Some(upload)
                } else {
                    durable_staged_uploads.remove(&format!("{}_{}", session_id, blob.blob.id))
                };
                if let Some(upload) = staged_upload {
                    if upload.received_bytes != blob.blob.size_bytes
                        || upload.blob.hash != blob.blob.hash
                        || upload.state != StagedBlobState::Uploaded
                    {
                        return Err(ApiError::bad_request(
                            "staged blob upload record does not match sync bundle",
                        ));
                    }
                    continue;
                }

                if blob.blob.size_bytes > MAX_IN_MEMORY_BLOB_BYTES {
                    let Some(blob_store) = &state.blob_store else {
                        return Err(ApiError::bad_request(
                            "streaming sync requires a configured blob store",
                        ));
                    };
                    if !blob_store
                        .exists(&blob.blob.hash)
                        .await
                        .map_err(storage_api_error)?
                    {
                        return Err(ApiError::bad_request(format!(
                            "streamed blob {} is missing from blob store",
                            blob.blob.hash.digest
                        )));
                    }
                    continue;
                }
                let mut descriptors = manifest
                    .chunks
                    .iter()
                    .filter(|descriptor| {
                        descriptor
                            .blob_hash
                            .as_ref()
                            .map(|hash| hash == &blob.blob.hash)
                            .unwrap_or(descriptor.hash == blob.blob.hash)
                    })
                    .collect::<Vec<_>>();
                descriptors.sort_by_key(|descriptor| descriptor.offset);
                if descriptors.is_empty() {
                    return Err(ApiError::bad_request("sync session missing blob chunks"));
                }
                let mut bytes = Vec::with_capacity(blob.blob.size_bytes as usize);
                for descriptor in descriptors {
                    let Some(chunk_bytes) = chunks_by_hash.get(&descriptor.hash) else {
                        return Err(ApiError::bad_request("sync session missing chunk bytes"));
                    };
                    bytes.extend_from_slice(chunk_bytes);
                }
                let computed = ContentBlob::from_bytes(
                    &bytes,
                    blob.blob.media_type.clone(),
                    blob.blob.visibility.clone(),
                );
                if computed.hash != blob.blob.hash || computed.size_bytes != blob.blob.size_bytes {
                    return Err(ApiError::bad_request("sync session blob checksum mismatch"));
                }
                blob.bytes = bytes;
            }
        }
        bundle
    };
    persist_bundle_blobs_to_store(&state, &bundle, false).await?;
    if let Some(store) = &state.durable_store {
        let transaction = transaction_from_sync_bundle(
            &bundle,
            Some(format!("sync-session:{session_id}")),
            "sync session commit".to_string(),
        )?;
        store
            .commit_transaction(transaction)
            .await
            .map_err(storage_api_error)?;
    }
    let session = {
        let mut registry = state
            .registry
            .write()
            .map_err(|_| ApiError::internal("registry lock poisoned"))?;
        apply_sync_bundle_to_registry(&mut registry, &bundle);
        registry
            .sync_chunks
            .retain(|(record_session_id, _), _| record_session_id != &session_id);
        registry
            .staged_blob_uploads
            .retain(|(record_session_id, _), _| record_session_id != &session_id);
        registry.sync_bundles.remove(&session_id);
        let Some(session) = registry.sync_sessions.get_mut(&session_id) else {
            return Err(ApiError::not_found("sync session not found"));
        };
        if session.repository_id != repository_id {
            return Err(ApiError::bad_request("sync session repository mismatch"));
        }
        session.state = SyncSessionState::Completed;
        session.clone()
    };
    persist_sync_session_state(&state, &session).await?;
    cleanup_sync_artifacts(&state, &repository_id, &session_id).await?;
    persist_state(&state).await?;
    emit_telemetry_event(
        state.clone(),
        telemetry_event(
            "sync.session.committed",
            TelemetrySource::Sync,
            TelemetrySeverity::Info,
            "sync session committed",
            NebulaTelemetryContext {
                repository_id: Some(repository_id),
                sync_session_id: Some(session_id),
                ..Default::default()
            },
            BTreeMap::new(),
        ),
    );
    Ok(Json(session))
}

async fn abort_sync_session(
    State(state): State<AppState>,
    Path((repository_id, session_id)): Path<(String, String)>,
) -> Result<Json<SyncSession>, ApiError> {
    let repository_id = RepositoryId::new(repository_id);
    let session_id = SyncSessionId::new(session_id);
    ensure_repo(&state, &repository_id)?;
    let session = {
        let mut registry = state
            .registry
            .write()
            .map_err(|_| ApiError::internal("registry lock poisoned"))?;
        let Some(session) = registry.sync_sessions.get_mut(&session_id) else {
            return Err(ApiError::not_found("sync session not found"));
        };
        if session.repository_id != repository_id {
            return Err(ApiError::bad_request("sync session repository mismatch"));
        }
        session.state = SyncSessionState::Aborted;
        let session = session.clone();
        registry
            .sync_chunks
            .retain(|(record_session_id, _), _| record_session_id != &session_id);
        session
    };
    persist_sync_session_state(&state, &session).await?;
    cleanup_sync_artifacts(&state, &repository_id, &session_id).await?;
    persist_state(&state).await?;
    emit_telemetry_event(
        state.clone(),
        telemetry_event(
            "sync.session.aborted",
            TelemetrySource::Sync,
            TelemetrySeverity::Warning,
            "sync session aborted",
            NebulaTelemetryContext {
                repository_id: Some(repository_id),
                sync_session_id: Some(session_id),
                ..Default::default()
            },
            BTreeMap::new(),
        ),
    );
    Ok(Json(session))
}

async fn get_sync_bundle(
    State(state): State<AppState>,
    Path(repository_id): Path<String>,
) -> Result<Json<RegistrySyncBundle>, ApiError> {
    let repository_id = RepositoryId::new(repository_id);
    ensure_repo(&state, &repository_id)?;
    let (
        refs,
        snapshots,
        changesets,
        proposals,
        operations,
        git_migration_records,
        environment_variables,
        environment_variable_versions,
        environments,
        cached_blobs,
    ) = {
        let registry = state
            .registry
            .read()
            .map_err(|_| ApiError::internal("registry lock poisoned"))?;
        let refs = registry
            .refs
            .values()
            .filter(|reference| reference.repository_id == repository_id)
            .cloned()
            .collect::<Vec<_>>();
        let snapshots = registry
            .snapshots
            .values()
            .filter(|snapshot| snapshot.repository_id == repository_id)
            .cloned()
            .collect::<Vec<_>>();
        let changesets = registry
            .changesets
            .values()
            .filter(|changeset| changeset.repository_id == repository_id)
            .cloned()
            .collect::<Vec<_>>();
        let proposals = registry
            .proposals
            .values()
            .filter(|proposal| proposal.repository_id == repository_id)
            .cloned()
            .collect::<Vec<_>>();
        let operations = registry
            .operations
            .values()
            .filter(|operation| operation.repository_id == repository_id)
            .cloned()
            .collect::<Vec<_>>();
        let git_migration_records = registry
            .git_migration_records
            .values()
            .filter(|record| record.repository_id == repository_id)
            .cloned()
            .collect::<Vec<_>>();
        let environment_variables = registry
            .environment_variables
            .values()
            .filter(|variable| variable.repository_id == repository_id)
            .cloned()
            .collect::<Vec<_>>();
        let environment_variable_versions = registry
            .environment_variable_versions
            .values()
            .filter(|version| version.repository_id == repository_id)
            .cloned()
            .collect::<Vec<_>>();
        let environments = registry
            .environments
            .values()
            .filter(|environment| environment.repository_id == repository_id)
            .cloned()
            .collect::<Vec<_>>();
        let reachable_hashes = snapshots
            .iter()
            .flat_map(|snapshot| snapshot.entries.iter())
            .filter_map(|entry| entry.hash.clone())
            .collect::<BTreeSet<_>>();
        let cached_blobs = reachable_hashes
            .into_iter()
            .filter_map(|hash| registry.blobs.get(&hash).cloned())
            .collect::<Vec<_>>();
        (
            refs,
            snapshots,
            changesets,
            proposals,
            operations,
            git_migration_records,
            environment_variables,
            environment_variable_versions,
            environments,
            cached_blobs,
        )
    };
    let blobs = fetch_bundle_blobs_from_store(&state, cached_blobs).await?;
    Ok(Json(RegistrySyncBundle {
        repository_id,
        default_ref: "main".to_string(),
        refs,
        snapshots,
        changesets,
        proposals,
        operations,
        git_migration_records,
        environment_variables,
        environment_variable_versions,
        environments,
        blobs,
    }))
}

async fn put_sync_bundle(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(repository_id): Path<String>,
    Json(bundle): Json<RegistrySyncBundle>,
) -> Result<Json<RegistrySyncBundle>, ApiError> {
    let repository_id = RepositoryId::new(repository_id);
    ensure_repo(&state, &repository_id)?;
    if bundle.repository_id != repository_id {
        return Err(ApiError::bad_request("sync bundle repository mismatch"));
    }
    persist_bundle_blobs_to_store(&state, &bundle, true).await?;
    if let Some(store) = &state.durable_store {
        let transaction = transaction_from_sync_bundle(
            &bundle,
            idempotency_key(&headers),
            "sync bundle commit".to_string(),
        )?;
        store
            .commit_transaction(transaction)
            .await
            .map_err(storage_api_error)?;
    }
    {
        let mut registry = state
            .registry
            .write()
            .map_err(|_| ApiError::internal("registry lock poisoned"))?;
        apply_sync_bundle_to_registry(&mut registry, &bundle);
    }
    persist_state(&state).await?;
    Ok(Json(bundle))
}

async fn put_vector_index_job(
    State(state): State<AppState>,
    Path(repository_id): Path<String>,
    Json(job): Json<VectorIndexJob>,
) -> Result<Json<VectorIndexJob>, ApiError> {
    ensure_repo_match(
        &state,
        &RepositoryId::new(repository_id),
        &job.repository_id,
    )?;
    durable_put_resource(
        &state,
        Some(&job.repository_id),
        "vector_index_job",
        job.id.as_str(),
        &job,
    )
    .await?;
    state
        .registry
        .write()
        .map_err(|_| ApiError::internal("registry lock poisoned"))?
        .vector_index_jobs
        .insert(job.id.clone(), job.clone());
    persist_state(&state).await?;
    Ok(Json(job))
}

async fn create_build_projection(
    State(state): State<AppState>,
    Path(repository_id): Path<String>,
    Json(request): Json<BuildProjectionRequest>,
) -> Result<Json<BuildProjectionResponse>, ApiError> {
    let repository_id = RepositoryId::new(repository_id);
    ensure_repo(&state, &repository_id)?;
    let response = execute_create_build_projection(&state, repository_id, request).await?;
    Ok(Json(response))
}

async fn execute_create_build_projection(
    state: &AppState,
    repository_id: RepositoryId,
    request: BuildProjectionRequest,
) -> Result<BuildProjectionResponse, ApiError> {
    if request.environment.repository_id != repository_id {
        return Err(ApiError::bad_request("environment repository mismatch"));
    }
    let snapshot =
        get_snapshot_for_repository(state, &repository_id, request.snapshot_id.clone()).await?;
    if snapshot.repository_id != repository_id {
        return Err(ApiError::bad_request("snapshot repository mismatch"));
    }

    let policies = {
        let registry = state
            .registry
            .read()
            .map_err(|_| ApiError::internal("registry lock poisoned"))?;
        registry.policies.values().cloned().collect::<Vec<_>>()
    };
    let engine = PolicyEngine::new(policies);
    let mut path_decisions = BTreeMap::new();
    let mut actions = Vec::new();

    for entry in snapshot
        .entries
        .iter()
        .filter(|entry| !matches!(entry.kind, TreeEntryKind::Directory))
        .filter(|entry| {
            request
                .path_scope
                .as_ref()
                .map(|scope| entry.path.starts_with(scope))
                .unwrap_or(true)
        })
    {
        let evaluation = engine.evaluate(&PolicyRequest {
            repository_id: repository_id.clone(),
            actor: request.actor.clone(),
            token_id: None,
            environment: Some(request.environment.clone()),
            action: PolicyAction::ReadBuildSource,
            object: PolicyObject::Path(entry.path.clone()),
            path: Some(entry.path.clone()),
            key: None,
            service_id: None,
            workspace_id: None,
            sensitivity: None,
            availability: None,
            deploy_source: None,
        });
        path_decisions.insert(entry.path.clone(), evaluation.decision.clone());
        actions.push(BuildProjectionAction {
            path: entry.path.clone(),
            decision: evaluation.decision,
            reason: evaluation.reason,
        });
    }

    let proposal = Proposal {
        id: ProposalId::generated(),
        repository_id: repository_id.clone(),
        title: "build projection".to_string(),
        target_ref_id: RefId::generated(),
        changeset_ids: Vec::new(),
        state: ReviewState::Open,
        policy_checks: Vec::new(),
    };
    let mut plan = nebula_git::plan_git_projection(
        &snapshot,
        &proposal,
        nebula_git::GitProjectionRequest {
            actor: request.actor,
            environment: request.environment,
            target: request.target,
            path_decisions,
        },
    )
    .map_err(|error| ApiError::bad_request(error.to_string()))?;
    plan.projection.policy_checks = actions
        .iter()
        .map(|action| PolicyCheck {
            actor: plan.projection.actor.clone(),
            environment_id: Some(plan.projection.environment_id.clone()),
            action: PolicyAction::ReadBuildSource,
            object: PolicyObject::Path(action.path.clone()),
            decision: action.decision.clone(),
            reason: action.reason.clone(),
        })
        .collect();

    state
        .registry
        .write()
        .map_err(|_| ApiError::internal("registry lock poisoned"))?
        .projections
        .insert(plan.projection.id.clone(), plan.projection.clone());
    persist_state(state).await?;

    Ok(BuildProjectionResponse {
        blocked: plan.has_blockers(),
        projection: plan.projection,
        manifest: plan.manifest,
        actions,
    })
}

fn galaxy_default_ref_name() -> &'static str {
    "main"
}

fn schedule_auto_deploys_for_ref(state: AppState, repository_id: RepositoryId, reference: Ref) {
    if reference.name != galaxy_default_ref_name() {
        tracing::debug!(
            repository_id = %repository_id,
            ref_name = %reference.name,
            "skipping auto-deploy; ref is not the galaxy default"
        );
        return;
    }
    tracing::info!(
        repository_id = %repository_id,
        ref_name = %reference.name,
        "scheduling push auto-deploys for default ref update"
    );
    tokio::spawn(async move {
        if let Err(error) =
            run_auto_deploys_for_default_ref(&state, &repository_id, &reference).await
        {
            tracing::warn!(
                error = %error.message,
                repository_id = %repository_id,
                ref_name = %reference.name,
                "auto-deploy after put_ref failed"
            );
        }
    });
}

async fn run_auto_deploys_for_default_ref(
    state: &AppState,
    repository_id: &RepositoryId,
    reference: &Ref,
) -> Result<(), ApiError> {
    let snapshot_id = resolve_ref_snapshot_id(state, repository_id, reference).await?;
    let configs = auto_deploy_configs_for_repo(state, repository_id).await?;
    if configs.is_empty() {
        tracing::info!(
            repository_id = %repository_id,
            "no horizon auto-deploy configs registered for galaxy"
        );
        return Ok(());
    }
    tracing::info!(
        repository_id = %repository_id,
        snapshot_id = %snapshot_id,
        config_count = configs.len(),
        "running push auto-deploys"
    );

    for config in configs {
        if let Err(error) =
            auto_deploy_for_config(state, repository_id, reference, &snapshot_id, &config).await
        {
            tracing::warn!(
                error = %error.message,
                repository_id = %repository_id,
                service_id = %config.service_id,
                snapshot_id = %snapshot_id,
                "failed to create push auto-deploy intent"
            );
        }
    }
    Ok(())
}

async fn auto_deploy_configs_for_repo(
    state: &AppState,
    repository_id: &RepositoryId,
) -> Result<Vec<RepositoryDeployConfig>, ApiError> {
    let mut configs = {
        let registry = state
            .registry
            .read()
            .map_err(|_| ApiError::internal("registry lock poisoned"))?;
        registry
            .deploy_configs
            .iter()
            .filter(|((id, _), config)| {
                id == repository_id
                    && config.auto_deploy
                    && config.provider_key.eq_ignore_ascii_case("horizon")
            })
            .map(|(_, config)| config.clone())
            .collect::<Vec<_>>()
    };
    if !configs.is_empty() {
        return Ok(configs);
    }

    // Durable store is the source of truth across restarts; memory may be cold.
    if let Some(store) = &state.durable_store {
        let resources = store
            .list_resources_scoped(Some(repository_id), "deploy_config")
            .await
            .map_err(storage_api_error)?;
        for value in resources {
            let config: RepositoryDeployConfig =
                serde_json::from_value(value).map_err(|error| {
                    ApiError::internal(format!("failed to decode deploy config: {error}"))
                })?;
            if config.repository_id == *repository_id
                && config.auto_deploy
                && config.provider_key.eq_ignore_ascii_case("horizon")
            {
                state
                    .registry
                    .write()
                    .map_err(|_| ApiError::internal("registry lock poisoned"))?
                    .deploy_configs
                    .insert(
                        (config.repository_id.clone(), config.service_id.clone()),
                        config.clone(),
                    );
                configs.push(config);
            }
        }
    }
    Ok(configs)
}

async fn auto_deploy_for_config(
    state: &AppState,
    repository_id: &RepositoryId,
    reference: &Ref,
    snapshot_id: &TreeSnapshotId,
    config: &RepositoryDeployConfig,
) -> Result<(), ApiError> {
    if has_inflight_deploy_intent(state, &config.service_id, snapshot_id)? {
        tracing::info!(
            repository_id = %repository_id,
            service_id = %config.service_id,
            snapshot_id = %snapshot_id,
            "skipping push auto-deploy; identical intent already in flight"
        );
        return Ok(());
    }

    let environment = resolve_auto_deploy_environment(state, repository_id, config)?;
    let projection_response = execute_create_build_projection(
        state,
        repository_id.clone(),
        BuildProjectionRequest {
            snapshot_id: snapshot_id.clone(),
            environment: environment.clone(),
            actor: Actor::Integration("horizon".to_string()),
            target: ProjectionTarget::Ci("horizon".to_string()),
            path_scope: config.context_path.clone(),
        },
    )
    .await?;
    if projection_response.blocked {
        return Err(ApiError::bad_request(
            "build projection blocked; skipping push auto-deploy",
        ));
    }

    execute_create_deploy_intent(
        state,
        repository_id.clone(),
        CreateDeployIntentRequest {
            projection_id: projection_response.projection.id,
            environment_id: environment.id,
            requested_provider_key: "horizon".to_string(),
            requested_by: Actor::Integration("horizon".to_string()),
            target: Some(DeployTarget {
                provider_key: config.provider_key.clone(),
                service_id: config.service_id.clone(),
                environment_name: config
                    .environment_name
                    .clone()
                    .or(Some(environment.name.clone())),
                context_path: config.context_path.clone(),
            }),
            release_gate_id: None,
            trigger_source: Some(DeployTriggerSource {
                kind: "push".to_string(),
                installation_id: None,
                event_id: None,
                reference: Some(reference.name.clone()),
            }),
        },
    )
    .await?;
    Ok(())
}

fn has_inflight_deploy_intent(
    state: &AppState,
    service_id: &str,
    snapshot_id: &TreeSnapshotId,
) -> Result<bool, ApiError> {
    let registry = state
        .registry
        .read()
        .map_err(|_| ApiError::internal("registry lock poisoned"))?;
    Ok(registry.deploy_intents.values().any(|intent| {
        intent.snapshot_id == *snapshot_id
            && intent
                .target
                .as_ref()
                .is_some_and(|target| target.service_id == service_id)
            && matches!(
                intent.state,
                DeployIntentState::Queued
                    | DeployIntentState::SentToAstracollab
                    | DeployIntentState::Running
            )
    }))
}

fn resolve_auto_deploy_environment(
    state: &AppState,
    repository_id: &RepositoryId,
    config: &RepositoryDeployConfig,
) -> Result<Environment, ApiError> {
    let registry = state
        .registry
        .read()
        .map_err(|_| ApiError::internal("registry lock poisoned"))?;
    let repo_environments = registry
        .environments
        .values()
        .filter(|environment| &environment.repository_id == repository_id)
        .cloned()
        .collect::<Vec<_>>();

    if let Some(environment_id) = &config.environment_id {
        if let Some(environment) = repo_environments
            .iter()
            .find(|environment| &environment.id == environment_id)
        {
            return Ok(environment.clone());
        }
        return Ok(Environment {
            id: environment_id.clone(),
            repository_id: repository_id.clone(),
            name: config
                .environment_name
                .clone()
                .unwrap_or_else(|| environment_id.as_str().to_string()),
            kind: EnvironmentKind::Custom(
                config
                    .environment_name
                    .clone()
                    .unwrap_or_else(|| "production".to_string()),
            ),
        });
    }

    if let Some(name) = &config.environment_name
        && let Some(environment) = repo_environments
            .iter()
            .find(|environment| environment.name.eq_ignore_ascii_case(name))
    {
        return Ok(environment.clone());
    }

    repo_environments.into_iter().next().ok_or_else(|| {
        ApiError::bad_request(format!(
            "no nebula environment available for auto-deploy of service {}",
            config.service_id
        ))
    })
}

async fn resolve_ref_snapshot_id(
    state: &AppState,
    repository_id: &RepositoryId,
    reference: &Ref,
) -> Result<TreeSnapshotId, ApiError> {
    let snapshot_id = {
        let registry = state
            .registry
            .read()
            .map_err(|_| ApiError::internal("registry lock poisoned"))?;
        match &reference.target {
            RefTarget::Snapshot(id) => Some(id.clone()),
            RefTarget::ChangeSet(id) => registry
                .changesets
                .get(id)
                .map(|changeset| changeset.next_snapshot_id.clone()),
            RefTarget::Proposal(id) => {
                let proposal = registry.proposals.get(id);
                proposal.and_then(|proposal| {
                    let changeset_id = proposal.changeset_ids.last()?;
                    registry
                        .changesets
                        .get(changeset_id)
                        .map(|changeset| changeset.next_snapshot_id.clone())
                })
            }
        }
    };

    let snapshot_id = if let Some(snapshot_id) = snapshot_id {
        snapshot_id
    } else {
        // Fall back to durable store for changesets/proposals not yet in memory.
        match &reference.target {
            RefTarget::Snapshot(id) => id.clone(),
            RefTarget::ChangeSet(id) => {
                let changeset = durable_get_resource::<ChangeSet>(
                    state,
                    Some(repository_id),
                    "changeset",
                    id.as_str(),
                )
                .await?
                .ok_or_else(|| ApiError::not_found("changeset not found for ref target"))?;
                changeset.next_snapshot_id
            }
            RefTarget::Proposal(id) => {
                let proposal = durable_get_resource::<Proposal>(
                    state,
                    Some(repository_id),
                    "proposal",
                    id.as_str(),
                )
                .await?
                .ok_or_else(|| ApiError::not_found("proposal not found for ref target"))?;
                let changeset_id = proposal.changeset_ids.last().ok_or_else(|| {
                    ApiError::bad_request("proposal has no changesets to resolve snapshot")
                })?;
                let changeset = durable_get_resource::<ChangeSet>(
                    state,
                    Some(repository_id),
                    "changeset",
                    changeset_id.as_str(),
                )
                .await?
                .ok_or_else(|| ApiError::not_found("changeset not found for proposal"))?;
                changeset.next_snapshot_id
            }
        }
    };

    // Ensure the snapshot is available for projection (memory or durable).
    let _ = get_snapshot_for_repository(state, repository_id, snapshot_id.clone()).await?;
    Ok(snapshot_id)
}

fn ensure_repo(state: &AppState, repository_id: &RepositoryId) -> Result<(), ApiError> {
    let registry = state
        .registry
        .read()
        .map_err(|_| ApiError::internal("registry lock poisoned"))?;
    if registry.repositories.contains_key(repository_id) {
        Ok(())
    } else {
        Err(ApiError::not_found(format!(
            "repository {repository_id} not found"
        )))
    }
}

fn ensure_repo_match(
    state: &AppState,
    route_repository_id: &RepositoryId,
    object_repository_id: &RepositoryId,
) -> Result<(), ApiError> {
    ensure_repo(state, route_repository_id)?;
    if route_repository_id != object_repository_id {
        return Err(ApiError::bad_request("repository mismatch"));
    }
    Ok(())
}

async fn durable_put_resource<T: Serialize>(
    state: &AppState,
    repository_id: Option<&RepositoryId>,
    kind: &str,
    id: &str,
    value: &T,
) -> Result<(), ApiError> {
    let Some(store) = &state.durable_store else {
        return Ok(());
    };
    let value = serde_json::to_value(value)
        .map_err(|error| ApiError::internal(format!("failed to encode {kind}: {error}")))?;
    store
        .put_resource(repository_id, kind, id, value)
        .await
        .map_err(storage_api_error)
}

async fn durable_get_resource<T: DeserializeOwned>(
    state: &AppState,
    repository_id: Option<&RepositoryId>,
    kind: &str,
    id: &str,
) -> Result<Option<T>, ApiError> {
    let Some(store) = &state.durable_store else {
        return Ok(None);
    };
    match store.get_resource_scoped(repository_id, kind, id).await {
        Ok(value) => serde_json::from_value(value)
            .map(Some)
            .map_err(|error| ApiError::internal(format!("failed to decode {kind}: {error}"))),
        Err(NebulaError::NotFound(_)) => Ok(None),
        Err(error) => Err(storage_api_error(error)),
    }
}

async fn durable_delete_resource(
    state: &AppState,
    repository_id: Option<&RepositoryId>,
    kind: &str,
    id: &str,
) -> Result<(), ApiError> {
    let Some(store) = &state.durable_store else {
        return Ok(());
    };
    store
        .delete_resource(repository_id, kind, id)
        .await
        .map_err(storage_api_error)
}

/// Batched variant of `durable_get_resource`: looks up every id in one round trip
/// and returns (id, value) pairs for the ones found.
async fn durable_get_resources_batch<T: DeserializeOwned>(
    state: &AppState,
    repository_id: Option<&RepositoryId>,
    kind: &str,
    ids: &[String],
) -> Result<Vec<(String, T)>, ApiError> {
    let Some(store) = &state.durable_store else {
        return Ok(Vec::new());
    };
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    store
        .get_resources_scoped_batch(repository_id, kind, ids)
        .await
        .map_err(storage_api_error)?
        .into_iter()
        .map(|(id, value)| {
            serde_json::from_value(value)
                .map(|decoded| (id, decoded))
                .map_err(|error| ApiError::internal(format!("failed to decode {kind}: {error}")))
        })
        .collect()
}

async fn durable_delete_resources_batch(
    state: &AppState,
    repository_id: Option<&RepositoryId>,
    kind: &str,
    ids: &[String],
) -> Result<(), ApiError> {
    let Some(store) = &state.durable_store else {
        return Ok(());
    };
    if ids.is_empty() {
        return Ok(());
    }
    store
        .delete_resources_batch(repository_id, kind, ids)
        .await
        .map_err(storage_api_error)
}

async fn persist_sync_session_state(
    state: &AppState,
    session: &SyncSession,
) -> Result<(), ApiError> {
    durable_put_resource(
        state,
        Some(&session.repository_id),
        "sync_session",
        session.id.as_str(),
        session,
    )
    .await
}

async fn persist_deploy_intent(state: &AppState, intent: &DeployIntent) -> Result<(), ApiError> {
    durable_put_resource(
        state,
        Some(&intent.repository_id),
        "deploy_intent",
        intent.id.as_str(),
        intent,
    )
    .await?;
    state
        .registry
        .write()
        .map_err(|_| ApiError::internal("registry lock poisoned"))?
        .deploy_intents
        .insert(intent.id.clone(), intent.clone());
    persist_state(state).await
}

async fn get_deploy_archive(
    State(state): State<AppState>,
    Path((repository_id, intent_id)): Path<(String, String)>,
    Query(query): Query<DeployArchiveQuery>,
) -> Result<Response, ApiError> {
    let repository_id = RepositoryId::new(repository_id);
    let intent_id = DeployIntentId::new(intent_id);
    verify_deploy_archive_signature(
        &state,
        &repository_id,
        &intent_id,
        query.expires_unix_ms,
        &query.signature,
    )?;
    if now_unix_ms() > query.expires_unix_ms {
        return Err(ApiError::bad_request("deploy archive URL has expired"));
    }

    let intent = deploy_intent_for_archive(&state, &repository_id, &intent_id).await?;
    let cache_key = deploy_archive_cache_key(&repository_id, &intent.snapshot_id);
    let cached = state
        .deploy_archive_cache
        .read()
        .map_err(|_| ApiError::internal("deploy archive cache lock poisoned"))?
        .get(&cache_key)
        .cloned();
    let bytes = if let Some(bytes) = cached {
        bytes
    } else {
        let built =
            Arc::new(build_deploy_archive(&state, &repository_id, &intent.projection_id).await?);
        state
            .deploy_archive_cache
            .write()
            .map_err(|_| ApiError::internal("deploy archive cache lock poisoned"))?
            .insert(cache_key, built.clone());
        built
    };

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/gzip")
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{intent_id}.tar.gz\""),
        )
        .body(Body::from(bytes.as_ref().clone()))
        .map_err(|error| ApiError::internal(format!("failed to build archive response: {error}")))
}

async fn deploy_archive_artifact(
    state: &AppState,
    repository_id: &RepositoryId,
    intent: &DeployIntent,
) -> Result<(String, String), ApiError> {
    let cache_key = deploy_archive_cache_key(repository_id, &intent.snapshot_id);
    let cached = state
        .deploy_archive_cache
        .read()
        .map_err(|_| ApiError::internal("deploy archive cache lock poisoned"))?
        .get(&cache_key)
        .cloned();
    let bytes = if let Some(bytes) = cached {
        bytes
    } else {
        let built =
            Arc::new(build_deploy_archive(state, repository_id, &intent.projection_id).await?);
        state
            .deploy_archive_cache
            .write()
            .map_err(|_| ApiError::internal("deploy archive cache lock poisoned"))?
            .insert(cache_key, built.clone());
        built
    };
    let mut hasher = Sha256::new();
    hasher.update(bytes.as_ref());
    let digest = hex::encode(hasher.finalize());
    let expires_unix_ms = now_unix_ms() + 10 * 60 * 1000;
    let signature = sign_deploy_archive(state, repository_id, &intent.id, expires_unix_ms)?;
    let path = format!(
        "/v1/deploy-archives/{}/{}?expires_unix_ms={}&signature={}",
        repository_id, intent.id, expires_unix_ms, signature
    );
    let uri = state
        .public_base_url
        .as_deref()
        .map(|base| format!("{}{}", base.trim_end_matches('/'), path))
        .unwrap_or(path);
    Ok((uri, digest))
}

fn deploy_archive_cache_key(repository_id: &RepositoryId, snapshot_id: &TreeSnapshotId) -> String {
    format!("{repository_id}:{snapshot_id}")
}

async fn deploy_intent_for_archive(
    state: &AppState,
    repository_id: &RepositoryId,
    intent_id: &DeployIntentId,
) -> Result<DeployIntent, ApiError> {
    if let Some(intent) = durable_get_resource::<DeployIntent>(
        state,
        Some(repository_id),
        "deploy_intent",
        intent_id.as_str(),
    )
    .await?
    {
        return Ok(intent);
    }

    state
        .registry
        .read()
        .map_err(|_| ApiError::internal("registry lock poisoned"))?
        .deploy_intents
        .get(intent_id)
        .cloned()
        .filter(|intent| &intent.repository_id == repository_id)
        .ok_or_else(|| ApiError::not_found("deploy intent not found"))
}

fn sign_deploy_archive(
    state: &AppState,
    repository_id: &RepositoryId,
    intent_id: &DeployIntentId,
    expires_unix_ms: u64,
) -> Result<String, ApiError> {
    let secret = state
        .astracollab_deploy_signing_secret
        .as_deref()
        .ok_or_else(|| {
            ApiError::bad_request(
                "ASTRACOLLAB_DEPLOY_SIGNING_SECRET is required for deploy archive signing",
            )
        })?;
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    hasher.update(b":deploy-archive:");
    hasher.update(repository_id.as_str().as_bytes());
    hasher.update(b":");
    hasher.update(intent_id.as_str().as_bytes());
    hasher.update(b":");
    hasher.update(expires_unix_ms.to_string().as_bytes());
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

fn verify_deploy_archive_signature(
    state: &AppState,
    repository_id: &RepositoryId,
    intent_id: &DeployIntentId,
    expires_unix_ms: u64,
    actual: &str,
) -> Result<(), ApiError> {
    let expected = sign_deploy_archive(state, repository_id, intent_id, expires_unix_ms)?;
    if !constant_time_eq(expected.as_bytes(), actual.as_bytes()) {
        return Err(ApiError::bad_request("invalid deploy archive signature"));
    }
    Ok(())
}

async fn build_deploy_archive(
    state: &AppState,
    repository_id: &RepositoryId,
    projection_id: &ProjectionId,
) -> Result<Vec<u8>, ApiError> {
    let projection = {
        let registry = state
            .registry
            .read()
            .map_err(|_| ApiError::internal("registry lock poisoned"))?;
        registry.projections.get(projection_id).cloned()
    }
    .ok_or_else(|| ApiError::not_found("projection not found"))?;
    if &projection.repository_id != repository_id {
        return Err(ApiError::bad_request("projection repository mismatch"));
    }
    let snapshot =
        get_snapshot_for_repository(state, repository_id, projection.snapshot_id).await?;

    let archive_entries: Vec<_> = snapshot
        .entries
        .iter()
        .filter(|entry| !matches!(entry.kind, TreeEntryKind::Directory) && entry.hash.is_some())
        .collect();

    let mut fetched_bytes = Vec::with_capacity(archive_entries.len());
    for chunk in archive_entries.chunks(BLOB_FETCH_CONCURRENCY) {
        let bytes = futures::future::try_join_all(
            chunk
                .iter()
                .map(|entry| blob_bytes_for_archive(state, entry.hash.as_ref().unwrap())),
        )
        .await?;
        fetched_bytes.extend(bytes);
    }

    let mut gzip = GzEncoder::new(Vec::new(), Compression::default());
    {
        let mut tar = TarBuilder::new(&mut gzip);
        for (entry, bytes) in archive_entries.iter().zip(fetched_bytes.iter()) {
            let mut header = TarHeader::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(if matches!(entry.kind, TreeEntryKind::Executable) {
                0o755
            } else {
                0o644
            });
            header.set_mtime(0);
            header.set_uid(0);
            header.set_gid(0);
            header.set_cksum();
            tar.append_data(&mut header, entry.path.as_str(), bytes.as_slice())
                .map_err(|error| {
                    ApiError::internal(format!("failed to append archive entry: {error}"))
                })?;
        }
        tar.finish().map_err(|error| {
            ApiError::internal(format!("failed to finish source archive: {error}"))
        })?;
    }
    gzip.finish()
        .map_err(|error| ApiError::internal(format!("failed to compress source archive: {error}")))
}

async fn blob_bytes_for_archive(state: &AppState, hash: &ContentHash) -> Result<Vec<u8>, ApiError> {
    if let Some((_, bytes)) = state
        .registry
        .read()
        .map_err(|_| ApiError::internal("registry lock poisoned"))?
        .blobs
        .get(hash)
        .cloned()
        && !bytes.is_empty()
    {
        return Ok(bytes);
    }

    if let Some(blob_store) = &state.blob_store {
        return blob_store.get(hash).await.map_err(storage_api_error);
    }

    Err(ApiError::not_found("blob not found for deploy archive"))
}

fn sign_deploy_handoff(
    state: &AppState,
    intent: &DeployIntent,
) -> Result<AstracollabDeployHandoff, ApiError> {
    let secret = state
        .astracollab_deploy_signing_secret
        .as_deref()
        .ok_or_else(|| {
            ApiError::bad_request(
                "ASTRACOLLAB_DEPLOY_SIGNING_SECRET is required for deploy handoff",
            )
        })?;
    let request_id = format!("astra-deploy-{}-{}", intent.id, intent.attempts + 1);
    let sent_at_unix_ms = now_unix_ms();
    let payload = serde_json::to_string(intent)
        .map_err(|error| ApiError::internal(format!("failed to encode deploy intent: {error}")))?;
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    hasher.update(b":");
    hasher.update(request_id.as_bytes());
    hasher.update(b":");
    hasher.update(sent_at_unix_ms.to_string().as_bytes());
    hasher.update(b":");
    hasher.update(payload.as_bytes());
    Ok(AstracollabDeployHandoff {
        request_id,
        endpoint: state.astracollab_deploy_url.clone(),
        signature: format!("sha256:{}", hex::encode(hasher.finalize())),
        sent_at_unix_ms,
    })
}

async fn cleanup_sync_artifacts(
    state: &AppState,
    repository_id: &RepositoryId,
    session_id: &SyncSessionId,
) -> Result<(), ApiError> {
    let manifest = {
        let memory_manifest = state
            .registry
            .read()
            .map_err(|_| ApiError::internal("registry lock poisoned"))?
            .chunk_manifests
            .get(session_id)
            .cloned();
        if memory_manifest.is_some() {
            memory_manifest
        } else {
            durable_get_resource::<ChunkTransferManifest>(
                state,
                Some(repository_id),
                "chunk_manifest",
                session_id.as_str(),
            )
            .await?
        }
    };
    if let Some(manifest) = manifest {
        let chunk_ids = manifest
            .chunks
            .iter()
            .map(|chunk| format!("{}_{}", session_id, BlobChunkId::from_hash(&chunk.hash)))
            .collect::<Vec<_>>();
        let blob_ids = manifest
            .chunks
            .iter()
            .filter_map(|chunk| chunk.blob_hash.as_ref())
            .map(|blob_hash| format!("{}_{}", session_id, BlobId::from_hash(blob_hash)))
            .collect::<Vec<_>>();
        durable_delete_resources_batch(state, Some(repository_id), "sync_chunk", &chunk_ids)
            .await?;
        durable_delete_resources_batch(state, Some(repository_id), "staged_blob_upload", &blob_ids)
            .await?;
    }
    durable_delete_resource(
        state,
        Some(repository_id),
        "sync_bundle",
        session_id.as_str(),
    )
    .await?;
    durable_delete_resource(
        state,
        Some(repository_id),
        "chunk_manifest",
        session_id.as_str(),
    )
    .await
}

async fn record_authorization_audit(
    state: &AppState,
    audit: &AuthorizationAudit,
) -> Result<(), ApiError> {
    if let Ok(value) = serde_json::to_value(audit) {
        state
            .registry
            .write()
            .map_err(|_| ApiError::internal("registry lock poisoned"))?
            .authorization_audits
            .push(value);
    }
    persist_state(state).await?;
    durable_put_resource(
        state,
        Some(&audit.repository_id),
        "authorization_audit",
        &authorization_audit_id(audit),
        audit,
    )
    .await
}

async fn record_denied_authorization_audit(
    state: &AppState,
    claims: &VerifiedClaims,
    repository_id: &RepositoryId,
    action: PolicyAction,
    resource_kind: &str,
    resource_id: String,
    reason: String,
) -> Result<(), ApiError> {
    let audit = AuthorizationAudit {
        actor: claims.actor.clone(),
        action,
        repository_id: repository_id.clone(),
        resource_kind: resource_kind.to_string(),
        resource_id: resource_id.clone(),
        path: Some(resource_id),
        environment: None,
        decision: PolicyDecision::Block,
        reason,
        engine: "nebula-registry-auth",
        matched_policy_ids: Vec::new(),
        timestamp_unix_ms: now_unix_ms(),
    };
    record_authorization_audit(state, &audit).await
}

fn authorization_audit_id(audit: &AuthorizationAudit) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    format!(
        "audit_{}_{}_{}_{}",
        audit.repository_id,
        audit.timestamp_unix_ms,
        nanos,
        audit_id_safe_name(&audit.resource_id)
    )
}

fn audit_id_safe_name(raw: &str) -> String {
    raw.chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

fn get_by_id<T>(
    state: &AppState,
    f: impl FnOnce(&InMemoryRegistry) -> Option<T>,
    not_found: &'static str,
) -> Result<Json<T>, ApiError> {
    let registry = state
        .registry
        .read()
        .map_err(|_| ApiError::internal("registry lock poisoned"))?;
    f(&registry)
        .map(Json)
        .ok_or_else(|| ApiError::not_found(not_found))
}

fn get_snapshot_from_state(
    state: &AppState,
    snapshot_id: TreeSnapshotId,
) -> Result<TreeSnapshot, ApiError> {
    let registry = state
        .registry
        .read()
        .map_err(|_| ApiError::internal("registry lock poisoned"))?;
    registry
        .snapshots
        .get(&snapshot_id)
        .cloned()
        .ok_or_else(|| ApiError::not_found("snapshot not found"))
}

async fn get_snapshot_for_repository(
    state: &AppState,
    repository_id: &RepositoryId,
    snapshot_id: TreeSnapshotId,
) -> Result<TreeSnapshot, ApiError> {
    if let Some(snapshot) = durable_get_resource::<TreeSnapshot>(
        state,
        Some(repository_id),
        "snapshot",
        snapshot_id.as_str(),
    )
    .await?
    {
        return Ok(snapshot);
    }
    let snapshot = get_snapshot_from_state(state, snapshot_id)?;
    if &snapshot.repository_id != repository_id {
        return Err(ApiError::not_found("snapshot not found"));
    }
    Ok(snapshot)
}

async fn hydrate_registry_from_store(
    store: &dyn RegistryStore,
    registry: &mut InMemoryRegistry,
) -> Result<(), ApiError> {
    load_resources(
        store,
        registry,
        "repository",
        |registry, repository: RepositoryRecord| {
            registry
                .repositories
                .insert(repository.id.clone(), repository);
        },
    )
    .await?;
    load_resources(store, registry, "blob", |registry, blob: ContentBlob| {
        registry
            .blobs
            .entry(blob.hash.clone())
            .or_insert_with(|| (blob, Vec::new()));
    })
    .await?;
    load_resources(store, registry, "oci_blob", |registry, blob: OciBlob| {
        registry
            .oci_blobs
            .entry(blob.digest.clone())
            .or_insert_with(|| (blob, Vec::new()));
    })
    .await?;
    // Keyed off the record itself rather than its storage id, so manifests
    // written before ids were scoped per repository (see `oci_manifest_id`)
    // still load into the right slot.
    load_resources(
        store,
        registry,
        "oci_manifest",
        |registry, manifest: OciManifest| {
            registry.oci_manifests.insert(
                (
                    manifest.repository_name_normalized.clone(),
                    manifest.digest.clone(),
                ),
                manifest,
            );
        },
    )
    .await?;
    load_resources(store, registry, "oci_tag", |registry, tag: OciTag| {
        registry.oci_tags.insert(
            (tag.repository_name_normalized.clone(), tag.tag.clone()),
            tag,
        );
    })
    .await?;
    load_resources(
        store,
        registry,
        "oci_upload_session",
        |registry, session: OciUploadSession| {
            registry
                .oci_upload_sessions
                .insert(session.uuid.clone(), session);
        },
    )
    .await?;
    load_resources(
        store,
        registry,
        "oci_provenance",
        |registry, provenance: OciProvenance| {
            registry
                .oci_provenance
                .insert(provenance.manifest_digest.clone(), provenance);
        },
    )
    .await?;
    load_resources(
        store,
        registry,
        "snapshot",
        |registry, snapshot: TreeSnapshot| {
            registry.snapshots.insert(snapshot.id.clone(), snapshot);
        },
    )
    .await?;
    load_resources(store, registry, "ref", |registry, reference: Ref| {
        registry.refs.insert(
            (reference.repository_id.clone(), reference.name.clone()),
            reference,
        );
    })
    .await?;
    load_resources(
        store,
        registry,
        "workspace",
        |registry, workspace: AgentWorkspace| {
            registry.workspaces.insert(workspace.id.clone(), workspace);
        },
    )
    .await?;
    load_resources(
        store,
        registry,
        "changeset",
        |registry, changeset: ChangeSet| {
            registry.changesets.insert(changeset.id.clone(), changeset);
        },
    )
    .await?;
    load_resources(
        store,
        registry,
        "proposal",
        |registry, proposal: Proposal| {
            registry.proposals.insert(proposal.id.clone(), proposal);
        },
    )
    .await?;
    load_resources(
        store,
        registry,
        "merge_intent",
        |registry, intent: MergeIntent| {
            registry.merge_intents.insert(intent.id.clone(), intent);
        },
    )
    .await?;
    load_resources(
        store,
        registry,
        "release_gate",
        |registry, gate: ReleaseGate| {
            registry.release_gates.insert(gate.id.clone(), gate);
        },
    )
    .await?;
    load_resources(
        store,
        registry,
        "environment",
        |registry, environment: Environment| {
            registry
                .environments
                .insert(environment.id.clone(), environment);
        },
    )
    .await?;
    load_resources(
        store,
        registry,
        "environment_variable",
        |registry, variable: EnvironmentVariable| {
            registry
                .environment_variables
                .insert(variable.id.clone(), variable);
        },
    )
    .await?;
    load_resources(
        store,
        registry,
        "environment_variable_version",
        |registry, version: EnvironmentVariableVersion| {
            registry
                .environment_variable_versions
                .insert(version.id.clone(), version);
        },
    )
    .await?;
    load_resources(
        store,
        registry,
        "environment_variable_change",
        |registry, change: EnvironmentVariableChange| {
            registry
                .environment_variable_changes
                .insert(change.id.clone(), change);
        },
    )
    .await?;
    load_resources(
        store,
        registry,
        "integration",
        |registry, integration: IntegrationActor| {
            registry
                .integrations
                .insert(integration.provider.clone(), integration);
        },
    )
    .await?;
    load_resources(
        store,
        registry,
        "policy",
        |registry, policy: VisibilityPolicy| {
            registry.policies.insert(policy.id.clone(), policy);
        },
    )
    .await?;
    load_resources(
        store,
        registry,
        "cedar_policy_document",
        |registry, document: StoredCedarPolicyDocument| {
            registry
                .cedar_policy_documents
                .insert(document.id.clone(), document);
        },
    )
    .await?;
    load_resources(
        store,
        registry,
        "vector_manifest",
        |registry, manifest: VectorIndexManifest| {
            registry
                .vector_manifests
                .insert(manifest.id.clone(), manifest);
        },
    )
    .await?;
    load_resources(
        store,
        registry,
        "projection",
        |registry, projection: Projection| {
            registry
                .projections
                .insert(projection.id.clone(), projection);
        },
    )
    .await?;
    load_resources(
        store,
        registry,
        "git_export",
        |registry, export: GitExport| {
            registry.git_exports.insert(export.id.clone(), export);
        },
    )
    .await?;
    load_resources(
        store,
        registry,
        "git_migration_record",
        |registry, record: GitMigrationRecord| {
            registry
                .git_migration_records
                .insert(record.id.clone(), record);
        },
    )
    .await?;
    load_resources(
        store,
        registry,
        "operation",
        |registry, operation: Operation| {
            registry.operations.insert(operation.id.clone(), operation);
        },
    )
    .await?;
    load_resources(
        store,
        registry,
        "deploy_intent",
        |registry, intent: DeployIntent| {
            registry.deploy_intents.insert(intent.id.clone(), intent);
        },
    )
    .await?;
    load_resources(
        store,
        registry,
        "deploy_config",
        |registry, config: RepositoryDeployConfig| {
            registry.deploy_configs.insert(
                (config.repository_id.clone(), config.service_id.clone()),
                config,
            );
        },
    )
    .await?;
    load_resources(
        store,
        registry,
        "deployment_grant",
        |registry, grant: DeploymentGrant| {
            registry.deployment_grants.insert(grant.id.clone(), grant);
        },
    )
    .await?;
    load_resources(
        store,
        registry,
        "auth_token",
        |registry, token: AuthToken| {
            registry.auth_tokens.insert(token.id.clone(), token);
        },
    )
    .await?;
    load_resources(
        store,
        registry,
        "proposal_comment",
        |registry, comment: ProposalComment| {
            registry
                .proposal_comments
                .insert(comment.id.clone(), comment);
        },
    )
    .await?;
    load_resources(
        store,
        registry,
        "proposal_check",
        |registry, check: ProposalStatusCheck| {
            registry.proposal_checks.insert(check.id.clone(), check);
        },
    )
    .await?;
    load_resources(
        store,
        registry,
        "webhook_endpoint",
        |registry, endpoint: WebhookEndpoint| {
            registry
                .webhook_endpoints
                .insert(endpoint.id.clone(), endpoint);
        },
    )
    .await?;
    load_resources(
        store,
        registry,
        "webhook_event",
        |registry, event: WebhookEvent| {
            registry.webhook_events.insert(event.id.clone(), event);
        },
    )
    .await?;
    load_resources(
        store,
        registry,
        "sync_session",
        |registry, session: SyncSession| {
            registry.sync_sessions.insert(session.id.clone(), session);
        },
    )
    .await?;
    load_resources(
        store,
        registry,
        "chunk_manifest",
        |registry, manifest: ChunkTransferManifest| {
            registry
                .chunk_manifests
                .insert(manifest.session_id.clone(), manifest);
        },
    )
    .await?;
    load_resources(
        store,
        registry,
        "sync_chunk",
        |registry, record: SyncChunkRecord| {
            registry
                .sync_chunks
                .insert((record.session_id.clone(), record.chunk.id.clone()), record);
        },
    )
    .await?;
    load_resources(
        store,
        registry,
        "vector_index_job",
        |registry, job: VectorIndexJob| {
            registry.vector_index_jobs.insert(job.id.clone(), job);
        },
    )
    .await?;
    Ok(())
}

async fn load_resources<T>(
    store: &dyn RegistryStore,
    registry: &mut InMemoryRegistry,
    kind: &str,
    mut insert: impl FnMut(&mut InMemoryRegistry, T),
) -> Result<(), ApiError>
where
    T: for<'de> Deserialize<'de>,
{
    let values = store
        .list_resources(kind)
        .await
        .map_err(storage_api_error)?;
    for value in values {
        let resource = serde_json::from_value(value)
            .map_err(|error| ApiError::internal(format!("failed to decode {kind}: {error}")))?;
        insert(registry, resource);
    }
    Ok(())
}

async fn persist_state(state: &AppState) -> Result<(), ApiError> {
    // When Postgres is configured it is the source of truth. Skipping the file
    // snapshot avoids cloning/pretty-printing the whole registry (OOM risk) and
    // prevents a truncated registry.json from masking durable state.
    if state.durable_store.is_some() {
        return Ok(());
    }

    let (registry, path) = {
        let registry = state
            .registry
            .read()
            .map_err(|_| ApiError::internal("registry lock poisoned"))?
            .clone();
        (registry, state.persistence_path.clone())
    };

    if let Some(path) = &path {
        registry
            .save_to_path(path)
            .map_err(|error| ApiError::internal(format!("failed to persist registry: {error}")))?;
    }

    Ok(())
}

async fn oci_v2_root(State(state): State<AppState>, request: Request<Body>) -> Response {
    if state.auth.required && request.headers().get(header::AUTHORIZATION).is_none() {
        return oci_auth_challenge(&state, None, "pull");
    }
    match *request.method() {
        Method::GET | Method::HEAD => oci_empty_response(StatusCode::OK, HeaderMap::new()),
        _ => oci_error(
            StatusCode::METHOD_NOT_ALLOWED,
            "UNSUPPORTED",
            "unsupported registry root method",
        ),
    }
}

async fn oci_dispatch(
    State(state): State<AppState>,
    Path(path): Path<String>,
    request: Request<Body>,
) -> Response {
    let method = request.method().clone();
    let uri = request.uri().clone();
    let headers = request.headers().clone();
    let query = uri.query().unwrap_or_default().to_string();

    if path.ends_with("/tags/list") {
        let repository = path.trim_end_matches("/tags/list");
        return oci_list_tags(state, &method, &headers, repository, &query).await;
    }
    if let Some((repository, reference)) = split_oci_path(&path, "/manifests/") {
        let body = match to_bytes(request.into_body(), 64 * 1024 * 1024).await {
            Ok(bytes) => bytes,
            Err(error) => {
                return oci_error(
                    StatusCode::BAD_REQUEST,
                    "MANIFEST_INVALID",
                    format!("failed to read manifest body: {error}"),
                );
            }
        };
        return oci_manifest(state, method, headers, repository, reference, body).await;
    }
    if let Some((repository, upload_uuid)) = split_oci_path(&path, "/blobs/uploads/") {
        let body = match to_bytes(request.into_body(), usize::MAX).await {
            Ok(bytes) => bytes,
            Err(error) => {
                return oci_error(
                    StatusCode::BAD_REQUEST,
                    "BLOB_UPLOAD_INVALID",
                    format!("failed to read upload body: {error}"),
                );
            }
        };
        return oci_upload_session(
            state,
            method,
            headers,
            repository,
            upload_uuid,
            &query,
            body,
        )
        .await;
    }
    if path.ends_with("/blobs/uploads") || path.ends_with("/blobs/uploads/") {
        let repository = path
            .trim_end_matches('/')
            .trim_end_matches("/blobs/uploads")
            .trim_end_matches('/');
        let body = match to_bytes(request.into_body(), usize::MAX).await {
            Ok(bytes) => bytes,
            Err(error) => {
                return oci_error(
                    StatusCode::BAD_REQUEST,
                    "BLOB_UPLOAD_INVALID",
                    format!("failed to read upload body: {error}"),
                );
            }
        };
        return oci_start_upload(state, method, headers, repository, &query, body).await;
    }
    if let Some((repository, digest)) = split_oci_path(&path, "/blobs/") {
        return oci_blob(state, method, headers, repository, digest).await;
    }
    oci_error(StatusCode::NOT_FOUND, "NAME_UNKNOWN", "unknown OCI route")
}

async fn oci_start_upload(
    state: AppState,
    method: Method,
    headers: HeaderMap,
    repository: &str,
    query: &str,
    body: Bytes,
) -> Response {
    if method != Method::POST {
        return oci_error(
            StatusCode::METHOD_NOT_ALLOWED,
            "UNSUPPORTED",
            "upload sessions require POST",
        );
    }
    let repository = match validate_oci_repository_name(repository) {
        Ok(repository) => repository,
        Err(response) => return response,
    };
    if let Err(error) = prune_expired_oci_upload_sessions(&state).await {
        return error.into_response();
    }
    if let Err(response) =
        verify_oci_request(&state, &headers, Some(&repository), PolicyAction::PushImage).await
    {
        return response;
    }

    let query_params = parse_query_params(query);
    if let Some(mount) = query_params.get("mount")
        && validate_oci_digest(mount).is_ok()
    {
        let blob = {
            let registry = state.registry.read().unwrap();
            registry.oci_blobs.get(mount).cloned()
        };
        if let Some((blob, bytes)) = blob {
            let now = now_unix_ms();
            let mounted = OciBlob {
                repository_name: repository.clone(),
                repository_name_normalized: repository.clone(),
                updated_at_unix_ms: now,
                ..blob
            };
            {
                let mut registry = state.registry.write().unwrap();
                registry.oci_blobs.insert(mount.clone(), (mounted, bytes));
            }
            if let Err(error) = persist_state(&state).await {
                return error.into_response();
            }
            let mut response_headers = HeaderMap::new();
            insert_header(
                &mut response_headers,
                "location",
                format!("/v2/{repository}/blobs/{mount}"),
            );
            insert_header(
                &mut response_headers,
                "docker-content-digest",
                mount.clone(),
            );
            return oci_empty_response(StatusCode::CREATED, response_headers);
        }
    }
    if let Some(digest) = query_params.get("digest")
        && !body.is_empty()
    {
        return oci_finalize_monolithic_upload(state, repository, digest, body).await;
    }

    let now = now_unix_ms();
    let uuid = format!("oci_upload_{}", AuthTokenId::generated().as_str());
    let session = OciUploadSession {
        schema_version: OCI_METADATA_SCHEMA_VERSION,
        uuid: uuid.clone(),
        repository_name: repository.clone(),
        repository_name_normalized: repository.clone(),
        partial_object_path: format!("oci/tmp/{repository}/{uuid}"),
        received_bytes: 0,
        bytes: Vec::new(),
        created_at_unix_ms: now,
        updated_at_unix_ms: now,
        expires_at_unix_ms: now.saturating_add(24 * 60 * 60 * 1_000),
    };
    {
        let mut registry = state.registry.write().unwrap();
        registry.oci_upload_sessions.insert(uuid.clone(), session);
    }
    let session = {
        let registry = state.registry.read().unwrap();
        registry.oci_upload_sessions.get(&uuid).cloned()
    };
    if let Some(session) = session
        && let Err(error) =
            durable_put_resource(&state, None, "oci_upload_session", &uuid, &session).await
    {
        return error.into_response();
    }
    if let Err(error) = persist_state(&state).await {
        return error.into_response();
    }
    let mut response_headers = HeaderMap::new();
    insert_header(
        &mut response_headers,
        "location",
        oci_upload_location(&repository, &uuid),
    );
    insert_header(&mut response_headers, "range", "0-0");
    insert_header(&mut response_headers, "docker-upload-uuid", uuid);
    oci_empty_response(StatusCode::ACCEPTED, response_headers)
}

async fn oci_upload_session(
    state: AppState,
    method: Method,
    headers: HeaderMap,
    repository: &str,
    upload_uuid: &str,
    query: &str,
    body: Bytes,
) -> Response {
    let repository = match validate_oci_repository_name(repository) {
        Ok(repository) => repository,
        Err(response) => return response,
    };
    if let Err(response) =
        verify_oci_request(&state, &headers, Some(&repository), PolicyAction::PushImage).await
    {
        return response;
    }
    let upload_uuid = upload_uuid.trim();
    if upload_uuid.is_empty() {
        return oci_error(
            StatusCode::NOT_FOUND,
            "BLOB_UPLOAD_UNKNOWN",
            "unknown upload session",
        );
    }

    match method {
        Method::GET => {
            let session = {
                let registry = state.registry.read().unwrap();
                registry.oci_upload_sessions.get(upload_uuid).cloned()
            };
            let Some(session) = session else {
                return oci_error(
                    StatusCode::NOT_FOUND,
                    "BLOB_UPLOAD_UNKNOWN",
                    "unknown upload session",
                );
            };
            let mut response_headers = HeaderMap::new();
            insert_header(
                &mut response_headers,
                "location",
                oci_upload_location(&repository, upload_uuid),
            );
            insert_header(
                &mut response_headers,
                "range",
                upload_range(session.received_bytes),
            );
            insert_header(
                &mut response_headers,
                "docker-upload-uuid",
                upload_uuid.to_string(),
            );
            oci_empty_response(StatusCode::NO_CONTENT, response_headers)
        }
        Method::PATCH => {
            let session = {
                let mut registry = state.registry.write().unwrap();
                let Some(session) = registry.oci_upload_sessions.get_mut(upload_uuid) else {
                    return oci_error(
                        StatusCode::NOT_FOUND,
                        "BLOB_UPLOAD_UNKNOWN",
                        "unknown upload session",
                    );
                };
                session.bytes.extend_from_slice(&body);
                session.received_bytes = session.bytes.len() as u64;
                session.updated_at_unix_ms = now_unix_ms();
                session.clone()
            };
            let mut response_headers = HeaderMap::new();
            insert_header(
                &mut response_headers,
                "location",
                oci_upload_location(&repository, upload_uuid),
            );
            insert_header(
                &mut response_headers,
                "range",
                upload_range(session.received_bytes),
            );
            insert_header(&mut response_headers, "docker-upload-uuid", session.uuid);
            oci_empty_response(StatusCode::ACCEPTED, response_headers)
        }
        Method::PUT => {
            let Some(digest) = parse_query_params(query).get("digest").cloned() else {
                return oci_error(
                    StatusCode::BAD_REQUEST,
                    "DIGEST_INVALID",
                    "digest query parameter is required",
                );
            };
            let bytes = {
                let mut registry = state.registry.write().unwrap();
                let Some(mut session) = registry.oci_upload_sessions.remove(upload_uuid) else {
                    return oci_error(
                        StatusCode::NOT_FOUND,
                        "BLOB_UPLOAD_UNKNOWN",
                        "unknown upload session",
                    );
                };
                session.bytes.extend_from_slice(&body);
                session.received_bytes = session.bytes.len() as u64;
                session.updated_at_unix_ms = now_unix_ms();
                session.bytes.clone()
            };
            let response = oci_store_blob(&state, &repository, &digest, bytes).await;
            if !response.status().is_success() {
                return response;
            }
            if let Err(error) =
                durable_delete_resource(&state, None, "oci_upload_session", upload_uuid).await
            {
                return error.into_response();
            }
            if let Err(error) = persist_state(&state).await {
                return error.into_response();
            }
            let mut response_headers = HeaderMap::new();
            insert_header(
                &mut response_headers,
                "location",
                format!("/v2/{repository}/blobs/{digest}"),
            );
            insert_header(&mut response_headers, "docker-content-digest", digest);
            oci_empty_response(StatusCode::CREATED, response_headers)
        }
        Method::DELETE => {
            let removed = {
                let mut registry = state.registry.write().unwrap();
                registry.oci_upload_sessions.remove(upload_uuid).is_some()
            };
            if !removed {
                return oci_error(
                    StatusCode::NOT_FOUND,
                    "BLOB_UPLOAD_UNKNOWN",
                    "unknown upload session",
                );
            }
            if let Err(error) =
                durable_delete_resource(&state, None, "oci_upload_session", upload_uuid).await
            {
                return error.into_response();
            }
            if let Err(error) = persist_state(&state).await {
                return error.into_response();
            }
            oci_empty_response(StatusCode::NO_CONTENT, HeaderMap::new())
        }
        _ => oci_error(
            StatusCode::METHOD_NOT_ALLOWED,
            "UNSUPPORTED",
            "unsupported upload method",
        ),
    }
}

async fn oci_finalize_monolithic_upload(
    state: AppState,
    repository: String,
    digest: &str,
    bytes: Bytes,
) -> Response {
    let response = oci_store_blob(&state, &repository, digest, bytes.to_vec()).await;
    if !response.status().is_success() {
        return response;
    }
    let mut headers = HeaderMap::new();
    insert_header(
        &mut headers,
        "location",
        format!("/v2/{repository}/blobs/{digest}"),
    );
    insert_header(&mut headers, "docker-content-digest", digest.to_string());
    oci_empty_response(StatusCode::CREATED, headers)
}

async fn oci_store_blob(
    state: &AppState,
    repository: &str,
    digest: &str,
    bytes: Vec<u8>,
) -> Response {
    if let Err(response) = validate_oci_digest(digest) {
        return response;
    }
    let computed = ContentHash::sha256(&bytes);
    let computed_digest = format!("{}:{}", computed.algorithm, computed.digest);
    if computed_digest != digest {
        return oci_error(
            StatusCode::BAD_REQUEST,
            "DIGEST_INVALID",
            "uploaded bytes do not match requested digest",
        );
    }
    if let Some(blob_store) = &state.blob_store
        && let Err(error) = blob_store.put(&computed, &bytes).await
    {
        return storage_api_error(error).into_response();
    }
    let now = now_unix_ms();
    let blob = OciBlob {
        schema_version: OCI_METADATA_SCHEMA_VERSION,
        repository_name: repository.to_string(),
        repository_name_normalized: repository.to_string(),
        digest: digest.to_string(),
        size_bytes: bytes.len() as u64,
        media_type: None,
        storage_key: format!("oci/blobs/{}/{}", computed.algorithm, computed.digest),
        created_at_unix_ms: now,
        updated_at_unix_ms: now,
    };
    let cached_bytes = if state.blob_store.is_some() {
        Vec::new()
    } else {
        bytes
    };
    {
        let mut registry = state.registry.write().unwrap();
        registry
            .oci_blobs
            .insert(digest.to_string(), (blob, cached_bytes));
    }
    let blob = {
        let registry = state.registry.read().unwrap();
        registry.oci_blobs.get(digest).map(|(blob, _)| blob.clone())
    };
    if let Some(blob) = blob
        && let Err(error) = durable_put_resource(state, None, "oci_blob", digest, &blob).await
    {
        return error.into_response();
    }
    if let Err(error) = persist_state(state).await {
        return error.into_response();
    }
    oci_empty_response(StatusCode::CREATED, HeaderMap::new())
}

async fn oci_blob(
    state: AppState,
    method: Method,
    headers: HeaderMap,
    repository: &str,
    digest: &str,
) -> Response {
    let repository = match validate_oci_repository_name(repository) {
        Ok(repository) => repository,
        Err(response) => return response,
    };
    if let Err(response) = validate_oci_digest(digest) {
        return response;
    }
    if let Err(response) =
        verify_oci_request(&state, &headers, Some(&repository), PolicyAction::PullImage).await
    {
        return response;
    }
    let blob = {
        let registry = state.registry.read().unwrap();
        registry.oci_blobs.get(digest).cloned()
    };
    let Some((blob, mut bytes)) = blob else {
        return oci_error(StatusCode::NOT_FOUND, "BLOB_UNKNOWN", "unknown blob");
    };
    if method != Method::GET && method != Method::HEAD {
        return oci_error(
            StatusCode::METHOD_NOT_ALLOWED,
            "UNSUPPORTED",
            "unsupported blob method",
        );
    }

    let range_header = headers.get(header::RANGE);
    let wants_range = range_header.is_some();
    let hash = content_hash_from_oci_digest(digest);

    // Stream full GETs from object store when bytes are not cached in memory.
    if bytes.is_empty()
        && !wants_range
        && method == Method::GET
        && let (Some(object_store), Some(hash)) = (&state.object_blob_store, hash.as_ref())
    {
        match object_store.get_byte_stream(hash).await {
            Ok((size, byte_stream)) => {
                let mut response_headers = HeaderMap::new();
                insert_header(
                    &mut response_headers,
                    "docker-content-digest",
                    digest.to_string(),
                );
                insert_header(&mut response_headers, "etag", format!(r#""{digest}""#));
                insert_header(
                    &mut response_headers,
                    "cache-control",
                    "public, max-age=31536000, immutable",
                );
                insert_header(
                    &mut response_headers,
                    "content-type",
                    blob.media_type
                        .unwrap_or_else(|| "application/octet-stream".to_string()),
                );
                insert_header(&mut response_headers, "content-length", size.to_string());
                return oci_stream_response(StatusCode::OK, response_headers, byte_stream);
            }
            Err(error) => return storage_api_error(error).into_response(),
        }
    }

    if bytes.is_empty()
        && let (Some(blob_store), Some(hash)) = (&state.blob_store, hash.as_ref())
    {
        match blob_store.get(hash).await {
            Ok(stored_bytes) => bytes = stored_bytes,
            Err(error) => return storage_api_error(error).into_response(),
        }
    }
    if bytes.is_empty()
        && method == Method::HEAD
        && let (Some(object_store), Some(hash)) = (&state.object_blob_store, hash.as_ref())
    {
        match object_store.object_size(hash).await {
            Ok(Some(size)) => {
                let mut response_headers = HeaderMap::new();
                insert_header(
                    &mut response_headers,
                    "docker-content-digest",
                    digest.to_string(),
                );
                insert_header(&mut response_headers, "etag", format!(r#""{digest}""#));
                insert_header(
                    &mut response_headers,
                    "content-type",
                    blob.media_type
                        .unwrap_or_else(|| "application/octet-stream".to_string()),
                );
                insert_header(&mut response_headers, "content-length", size.to_string());
                return oci_empty_response(StatusCode::OK, response_headers);
            }
            Ok(None) => return oci_error(StatusCode::NOT_FOUND, "BLOB_UNKNOWN", "unknown blob"),
            Err(error) => return storage_api_error(error).into_response(),
        }
    }

    let range = range_header
        .and_then(|value| value.to_str().ok())
        .and_then(|value| parse_byte_range(value, bytes.len() as u64));
    let mut response_headers = HeaderMap::new();
    insert_header(
        &mut response_headers,
        "docker-content-digest",
        digest.to_string(),
    );
    insert_header(&mut response_headers, "etag", format!(r#""{digest}""#));
    insert_header(
        &mut response_headers,
        "cache-control",
        "public, max-age=31536000, immutable",
    );
    insert_header(
        &mut response_headers,
        "content-type",
        blob.media_type
            .unwrap_or_else(|| "application/octet-stream".to_string()),
    );
    if let Some((start, end)) = range {
        let body = if method == Method::HEAD {
            Vec::new()
        } else {
            bytes[start as usize..=end as usize].to_vec()
        };
        insert_header(
            &mut response_headers,
            "content-range",
            format!("bytes {start}-{end}/{}", bytes.len()),
        );
        insert_header(
            &mut response_headers,
            "content-length",
            (end - start + 1).to_string(),
        );
        return oci_body_response(StatusCode::PARTIAL_CONTENT, response_headers, body);
    }
    if range_header.is_some() {
        let mut response_headers = HeaderMap::new();
        insert_header(
            &mut response_headers,
            "content-range",
            format!("bytes */{}", bytes.len()),
        );
        return oci_empty_response(StatusCode::RANGE_NOT_SATISFIABLE, response_headers);
    }
    insert_header(
        &mut response_headers,
        "content-length",
        bytes.len().to_string(),
    );
    let body = if method == Method::HEAD {
        Vec::new()
    } else {
        bytes
    };
    oci_body_response(StatusCode::OK, response_headers, body)
}

async fn oci_manifest(
    state: AppState,
    method: Method,
    headers: HeaderMap,
    repository: &str,
    reference: &str,
    body: Bytes,
) -> Response {
    let repository = match validate_oci_repository_name(repository) {
        Ok(repository) => repository,
        Err(response) => return response,
    };
    if validate_oci_digest(reference).is_err() && validate_oci_tag(reference).is_err() {
        return oci_error(
            StatusCode::BAD_REQUEST,
            "TAG_INVALID",
            "invalid manifest reference",
        );
    }
    match method {
        Method::PUT => {
            if let Err(response) =
                verify_oci_request(&state, &headers, Some(&repository), PolicyAction::PushImage)
                    .await
            {
                return response;
            }
            let media_type = headers
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .unwrap_or("application/vnd.oci.image.manifest.v1+json")
                .to_string();
            if !is_supported_manifest_media_type(&media_type) {
                return oci_error(
                    StatusCode::UNSUPPORTED_MEDIA_TYPE,
                    "MANIFEST_INVALID",
                    "unsupported manifest media type",
                );
            }
            let digest = ContentHash::sha256(&body);
            let digest = format!("{}:{}", digest.algorithm, digest.digest);
            let referenced_digests = match collect_manifest_digests(&body) {
                Ok(digests) => digests,
                Err(response) => return response,
            };
            {
                let registry = state.registry.read().unwrap();
                for referenced in &referenced_digests {
                    if referenced == &digest {
                        continue;
                    }
                    let has_blob = registry.oci_blobs.contains_key(referenced);
                    let has_manifest = registry
                        .oci_manifests
                        .contains_key(&(repository.clone(), referenced.clone()));
                    if !has_blob && !has_manifest {
                        return oci_error(
                            StatusCode::BAD_REQUEST,
                            "MANIFEST_BLOB_UNKNOWN",
                            format!("manifest references missing digest {referenced}"),
                        );
                    }
                }
            }
            let now = now_unix_ms();
            let manifest = OciManifest {
                schema_version: OCI_METADATA_SCHEMA_VERSION,
                repository_name: repository.clone(),
                repository_name_normalized: repository.clone(),
                reference: Some(reference.to_string()),
                digest: digest.clone(),
                media_type,
                size_bytes: body.len() as u64,
                bytes: body.to_vec(),
                referenced_digests,
                created_at_unix_ms: now,
                updated_at_unix_ms: now,
            };
            let tag = if validate_oci_digest(reference).is_err() {
                Some(OciTag {
                    schema_version: OCI_METADATA_SCHEMA_VERSION,
                    repository_name: repository.clone(),
                    repository_name_normalized: repository.clone(),
                    tag: reference.to_string(),
                    manifest_digest: digest.clone(),
                    actor: request_actor(&headers),
                    created_at_unix_ms: now,
                    updated_at_unix_ms: now,
                })
            } else {
                None
            };
            let provenance = OciProvenance {
                schema_version: OCI_METADATA_SCHEMA_VERSION,
                manifest_digest: digest.clone(),
                repository_name: repository.clone(),
                repository_name_normalized: repository.clone(),
                nebula_repository_id: None,
                snapshot_id: None,
                projection_id: None,
                deploy_intent_id: None,
                actor: tag.as_ref().and_then(|tag| tag.actor.clone()),
                policy_digest: header_string(&headers, "x-nebula-policy-digest"),
                build_id: header_string(&headers, "x-nebula-build-id"),
                created_at_unix_ms: now,
                updated_at_unix_ms: now,
            };
            {
                let mut registry = state.registry.write().unwrap();
                registry
                    .oci_manifests
                    .insert((repository.clone(), digest.clone()), manifest);
                if let Some(tag) = tag {
                    registry
                        .oci_tags
                        .insert((repository.clone(), tag.tag.clone()), tag);
                }
                registry.oci_provenance.insert(digest.clone(), provenance);
            }
            let (manifest, tag, provenance) = {
                let registry = state.registry.read().unwrap();
                (
                    registry
                        .oci_manifests
                        .get(&(repository.clone(), digest.clone()))
                        .cloned(),
                    registry
                        .oci_tags
                        .get(&(repository.clone(), reference.to_string()))
                        .cloned(),
                    registry.oci_provenance.get(&digest).cloned(),
                )
            };
            if let Some(manifest) = manifest {
                let id = oci_manifest_id(&repository, &digest);
                if let Err(error) =
                    durable_put_resource(&state, None, "oci_manifest", &id, &manifest).await
                {
                    return error.into_response();
                }
            }
            if let Some(tag) = tag {
                let id = format!("{}:{}", repository, tag.tag);
                if let Err(error) = durable_put_resource(&state, None, "oci_tag", &id, &tag).await {
                    return error.into_response();
                }
            }
            if let Some(provenance) = provenance
                && let Err(error) =
                    durable_put_resource(&state, None, "oci_provenance", &digest, &provenance).await
            {
                return error.into_response();
            }
            if let Err(error) = persist_state(&state).await {
                return error.into_response();
            }
            let mut response_headers = HeaderMap::new();
            insert_header(
                &mut response_headers,
                "location",
                format!("/v2/{repository}/manifests/{digest}"),
            );
            insert_header(&mut response_headers, "docker-content-digest", digest);
            oci_empty_response(StatusCode::CREATED, response_headers)
        }
        Method::GET | Method::HEAD => {
            if let Err(response) =
                verify_oci_request(&state, &headers, Some(&repository), PolicyAction::PullImage)
                    .await
            {
                return response;
            }
            let Some(manifest) = resolve_oci_manifest(&state, &repository, reference) else {
                return oci_error(
                    StatusCode::NOT_FOUND,
                    "MANIFEST_UNKNOWN",
                    "unknown manifest",
                );
            };
            if !accepts_manifest(&headers, &manifest.media_type) {
                return oci_error(
                    StatusCode::NOT_FOUND,
                    "MANIFEST_UNKNOWN",
                    "requested manifest media type is unavailable",
                );
            }
            let mut response_headers = HeaderMap::new();
            insert_header(
                &mut response_headers,
                "docker-content-digest",
                manifest.digest.clone(),
            );
            insert_header(
                &mut response_headers,
                "content-type",
                manifest.media_type.clone(),
            );
            insert_header(
                &mut response_headers,
                "content-length",
                manifest.bytes.len().to_string(),
            );
            insert_header(
                &mut response_headers,
                "etag",
                format!(r#""{}""#, manifest.digest),
            );
            if validate_oci_digest(reference).is_ok() {
                insert_header(
                    &mut response_headers,
                    "cache-control",
                    "public, max-age=31536000, immutable",
                );
            } else {
                insert_header(&mut response_headers, "cache-control", "no-cache");
            }
            let body = if method == Method::HEAD {
                Vec::new()
            } else {
                manifest.bytes
            };
            oci_body_response(StatusCode::OK, response_headers, body)
        }
        _ => oci_error(
            StatusCode::METHOD_NOT_ALLOWED,
            "UNSUPPORTED",
            "unsupported manifest method",
        ),
    }
}

async fn oci_list_tags(
    state: AppState,
    method: &Method,
    headers: &HeaderMap,
    repository: &str,
    query: &str,
) -> Response {
    if method != Method::GET {
        return oci_error(
            StatusCode::METHOD_NOT_ALLOWED,
            "UNSUPPORTED",
            "tag listing requires GET",
        );
    }
    let repository = match validate_oci_repository_name(repository) {
        Ok(repository) => repository,
        Err(response) => return response,
    };
    if let Err(response) =
        verify_oci_request(&state, headers, Some(&repository), PolicyAction::PullImage).await
    {
        return response;
    }
    let params = parse_query_params(query);
    let n = params
        .get("n")
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0);
    let last = params.get("last").cloned();
    let mut tags: Vec<String> = {
        let registry = state.registry.read().unwrap();
        registry
            .oci_tags
            .keys()
            .filter_map(|(repo, tag)| {
                if repo == &repository {
                    Some(tag.clone())
                } else {
                    None
                }
            })
            .collect()
    };
    tags.sort();
    if let Some(last) = last {
        tags.retain(|tag| tag > &last);
    }
    let next = n.and_then(|limit| tags.get(limit).cloned());
    if let Some(limit) = n {
        tags.truncate(limit);
    }
    let mut response_headers = HeaderMap::new();
    insert_header(&mut response_headers, "content-type", "application/json");
    if let Some(next) = next {
        insert_header(
            &mut response_headers,
            "link",
            format!(
                r#"</v2/{repository}/tags/list?n={}&last={next}>; rel="next""#,
                tags.len()
            ),
        );
    }
    oci_body_response(
        StatusCode::OK,
        response_headers,
        serde_json::to_vec(&json!({ "name": repository, "tags": tags })).unwrap_or_default(),
    )
}

fn resolve_oci_manifest(
    state: &AppState,
    repository: &str,
    reference: &str,
) -> Option<OciManifest> {
    let registry = state.registry.read().unwrap();
    let digest = if validate_oci_digest(reference).is_ok() {
        reference.to_string()
    } else {
        registry
            .oci_tags
            .get(&(repository.to_string(), reference.to_string()))?
            .manifest_digest
            .clone()
    };
    registry
        .oci_manifests
        .get(&(repository.to_string(), digest))
        .cloned()
}

async fn prune_expired_oci_upload_sessions(state: &AppState) -> Result<(), ApiError> {
    let now = now_unix_ms();
    let expired = {
        let mut registry = state
            .registry
            .write()
            .map_err(|_| ApiError::internal("registry lock poisoned"))?;
        let expired = registry
            .oci_upload_sessions
            .iter()
            .filter_map(|(uuid, session)| {
                if session.expires_at_unix_ms <= now {
                    Some(uuid.clone())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        for uuid in &expired {
            registry.oci_upload_sessions.remove(uuid);
        }
        expired
    };
    for uuid in expired {
        durable_delete_resource(state, None, "oci_upload_session", &uuid).await?;
        tracing::info!(upload_uuid = %uuid, "pruned expired OCI upload session");
    }
    persist_state(state).await
}

async fn verify_oci_request(
    state: &AppState,
    headers: &HeaderMap,
    repository: Option<&str>,
    action: PolicyAction,
) -> Result<Option<Actor>, Response> {
    if !state.auth.required {
        return Ok(None);
    }
    let Some(auth_header) = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
    else {
        return Err(oci_auth_challenge(
            state,
            repository,
            oci_action_name(&action),
        ));
    };
    let verified = if let Some(token) = auth_header.strip_prefix("Bearer ").map(str::trim) {
        verify_oci_bearer(state, token).await
    } else if let Some(encoded) = auth_header.strip_prefix("Basic ").map(str::trim) {
        let Some(decoded) = decode_basic_credentials(encoded) else {
            return Err(oci_auth_challenge(
                state,
                repository,
                oci_action_name(&action),
            ));
        };
        let token = decoded
            .split_once(':')
            .map(|(_, password)| password)
            .unwrap_or(decoded.as_str());
        verify_stored_api_token(state, token, None)
    } else {
        return Err(oci_auth_challenge(
            state,
            repository,
            oci_action_name(&action),
        ));
    };
    let verified = match verified {
        Ok(verified) => verified,
        Err(_) => {
            return Err(oci_auth_challenge(
                state,
                repository,
                oci_action_name(&action),
            ));
        }
    };
    if !oci_scope_allows(&verified.scopes, &action) {
        return Err(oci_error(
            StatusCode::FORBIDDEN,
            "DENIED",
            "token is not allowed for this registry action",
        ));
    }
    Ok(Some(verified.actor))
}

async fn verify_oci_bearer(state: &AppState, token: &str) -> Result<VerifiedClaims, String> {
    if let Some(provider) = &state.external_auth_provider {
        return provider.verify_bearer(token, None).await;
    }
    if let Some(verifier) = &state.auth.verifier
        && let Ok(context) = verifier.verify_token(token).await
    {
        return Ok(context.into());
    }
    verify_stored_api_token(state, token, None).map_err(|error| error.to_string())
}

fn oci_scope_allows(scopes: &[PolicyAction], action: &PolicyAction) -> bool {
    scopes.contains(action)
        || (matches!(action, PolicyAction::PullImage) && scopes.contains(&PolicyAction::ReadBlob))
        || (matches!(action, PolicyAction::PushImage)
            && scopes.contains(&PolicyAction::SyncObjects))
}

fn oci_action_name(action: &PolicyAction) -> &'static str {
    match action {
        PolicyAction::PushImage => "push",
        _ => "pull",
    }
}

#[allow(clippy::result_large_err)]
fn validate_oci_repository_name(raw: &str) -> Result<String, Response> {
    let name = raw.trim_matches('/');
    if name.is_empty() || name.len() > 255 {
        return Err(oci_error(
            StatusCode::BAD_REQUEST,
            "NAME_INVALID",
            "invalid OCI repository name",
        ));
    }
    if name.contains('%') || name.contains('\\') || name.contains("//") {
        return Err(oci_error(
            StatusCode::BAD_REQUEST,
            "NAME_INVALID",
            "invalid OCI repository name",
        ));
    }
    for segment in name.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(oci_error(
                StatusCode::BAD_REQUEST,
                "NAME_INVALID",
                "invalid OCI repository name",
            ));
        }
        let valid = segment.chars().all(|ch| {
            ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '.' | '_' | '-')
        });
        if !valid || segment.starts_with('.') || segment.ends_with('.') {
            return Err(oci_error(
                StatusCode::BAD_REQUEST,
                "NAME_INVALID",
                "invalid OCI repository name",
            ));
        }
    }
    Ok(name.to_string())
}

#[allow(clippy::result_large_err)]
fn validate_oci_digest(raw: &str) -> Result<(), Response> {
    let Some(digest) = raw.strip_prefix("sha256:") else {
        return Err(oci_error(
            StatusCode::BAD_REQUEST,
            "DIGEST_INVALID",
            "only sha256 digests are supported",
        ));
    };
    if digest.len() != 64 || !digest.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(oci_error(
            StatusCode::BAD_REQUEST,
            "DIGEST_INVALID",
            "invalid sha256 digest",
        ));
    }
    Ok(())
}

fn content_hash_from_oci_digest(raw: &str) -> Option<ContentHash> {
    let digest = raw.strip_prefix("sha256:")?;
    Some(ContentHash {
        algorithm: "sha256".to_string(),
        digest: digest.to_string(),
    })
}

#[allow(clippy::result_large_err)]
fn validate_oci_tag(raw: &str) -> Result<(), Response> {
    if raw.is_empty() || raw.len() > 128 || raw.starts_with('.') || raw.starts_with('-') {
        return Err(oci_error(
            StatusCode::BAD_REQUEST,
            "TAG_INVALID",
            "invalid OCI tag",
        ));
    }
    let valid = raw
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | '-'));
    if !valid {
        return Err(oci_error(
            StatusCode::BAD_REQUEST,
            "TAG_INVALID",
            "invalid OCI tag",
        ));
    }
    Ok(())
}

fn is_supported_manifest_media_type(media_type: &str) -> bool {
    matches!(
        media_type,
        "application/vnd.oci.image.manifest.v1+json"
            | "application/vnd.oci.image.index.v1+json"
            | "application/vnd.docker.distribution.manifest.v2+json"
            | "application/vnd.docker.distribution.manifest.list.v2+json"
            | "application/vnd.buildkit.cacheconfig.v0"
    )
}

#[allow(clippy::result_large_err)]
fn collect_manifest_digests(bytes: &[u8]) -> Result<Vec<String>, Response> {
    let value: Value = serde_json::from_slice(bytes).map_err(|_| {
        oci_error(
            StatusCode::BAD_REQUEST,
            "MANIFEST_INVALID",
            "manifest body must be JSON",
        )
    })?;
    let mut digests = BTreeSet::new();
    collect_digest_values(&value, &mut digests);
    Ok(digests.into_iter().collect())
}

fn collect_digest_values(value: &Value, digests: &mut BTreeSet<String>) {
    match value {
        Value::Object(map) => {
            if let Some(Value::String(digest)) = map.get("digest")
                && validate_oci_digest(digest).is_ok()
            {
                digests.insert(digest.clone());
            }
            for value in map.values() {
                collect_digest_values(value, digests);
            }
        }
        Value::Array(values) => {
            for value in values {
                collect_digest_values(value, digests);
            }
        }
        _ => {}
    }
}

fn accepts_manifest(headers: &HeaderMap, media_type: &str) -> bool {
    let Some(accept) = headers
        .get(header::ACCEPT)
        .and_then(|value| value.to_str().ok())
    else {
        return true;
    };
    accept
        .split(',')
        .map(|value| value.split(';').next().unwrap_or_default().trim())
        .any(|value| value == "*/*" || value == media_type || value == "application/json")
}

fn split_oci_path<'a>(path: &'a str, marker: &str) -> Option<(&'a str, &'a str)> {
    let index = path.rfind(marker)?;
    let repository = &path[..index];
    let value = &path[index + marker.len()..];
    if repository.is_empty() || value.is_empty() {
        return None;
    }
    Some((repository, value))
}

fn parse_query_params(query: &str) -> BTreeMap<String, String> {
    query
        .split('&')
        .filter_map(|part| {
            if part.is_empty() {
                return None;
            }
            let (key, value) = part.split_once('=').unwrap_or((part, ""));
            Some((key.to_string(), percent_decode(value)))
        })
        .collect()
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut result = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = char::from(bytes[i + 1]).to_digit(16);
            let lo = char::from(bytes[i + 2]).to_digit(16);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                result.push(((hi << 4) | lo) as u8);
                i += 3;
                continue;
            }
        }
        result.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&result).into_owned()
}

fn parse_byte_range(value: &str, size: u64) -> Option<(u64, u64)> {
    let range = value.strip_prefix("bytes=")?;
    let (start, end) = range.split_once('-')?;
    let start = start.parse::<u64>().ok()?;
    let end = if end.is_empty() {
        size.checked_sub(1)?
    } else {
        end.parse::<u64>().ok()?
    };
    if start > end || end >= size {
        return None;
    }
    Some((start, end))
}

fn upload_range(received_bytes: u64) -> String {
    if received_bytes == 0 {
        "0-0".to_string()
    } else {
        format!("0-{}", received_bytes - 1)
    }
}

fn oci_upload_location(repository: &str, upload_uuid: &str) -> String {
    // Deliberately relative, not built from public_base_url: OCI clients resolve a
    // relative Location against whatever host they actually connected to. Emitting
    // an absolute external URL here breaks in-cluster clients (e.g. BuildKit hitting
    // the internal Service address), since most HTTP clients won't forward the
    // Authorization header across a host change on redirect, silently turning the
    // upload-continuation request unauthenticated.
    format!("/v2/{repository}/blobs/uploads/{upload_uuid}")
}

fn request_actor(headers: &HeaderMap) -> Option<Actor> {
    header_string(headers, "x-nebula-actor").map(Actor::User)
}

fn header_string(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn decode_basic_credentials(encoded: &str) -> Option<String> {
    let mut output = Vec::new();
    let mut buffer = 0u32;
    let mut bits = 0u8;
    for byte in encoded.bytes().filter(|byte| !byte.is_ascii_whitespace()) {
        if byte == b'=' {
            break;
        }
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        } as u32;
        buffer = (buffer << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    String::from_utf8(output).ok()
}

fn oci_auth_challenge(_state: &AppState, _repository: Option<&str>, _action: &str) -> Response {
    let mut headers = HeaderMap::new();
    insert_header(
        &mut headers,
        "www-authenticate",
        r#"Basic realm="nebula-registry""#,
    );
    oci_error_with_headers(
        StatusCode::UNAUTHORIZED,
        "UNAUTHORIZED",
        "authentication required",
        headers,
    )
}

fn oci_error(status: StatusCode, code: &str, message: impl Into<String>) -> Response {
    oci_error_with_headers(status, code, message, HeaderMap::new())
}

fn oci_error_with_headers(
    status: StatusCode,
    code: &str,
    message: impl Into<String>,
    headers: HeaderMap,
) -> Response {
    let body = serde_json::to_vec(&json!({
        "errors": [
            {
                "code": code,
                "message": message.into()
            }
        ]
    }))
    .unwrap_or_default();
    oci_body_response(status, headers, body)
}

fn oci_empty_response(status: StatusCode, headers: HeaderMap) -> Response {
    oci_body_response(status, headers, Vec::new())
}

fn oci_body_response(status: StatusCode, mut headers: HeaderMap, body: Vec<u8>) -> Response {
    headers.insert(
        HeaderName::from_static("docker-distribution-api-version"),
        HeaderValue::from_static("registry/2.0"),
    );
    let mut response = (status, Body::from(body)).into_response();
    response.headers_mut().extend(headers);
    response
}

fn oci_stream_response<S>(status: StatusCode, mut headers: HeaderMap, stream: S) -> Response
where
    S: futures::Stream<Item = Result<Bytes, std::io::Error>> + Send + 'static,
{
    headers.insert(
        HeaderName::from_static("docker-distribution-api-version"),
        HeaderValue::from_static("registry/2.0"),
    );
    let mut response = (status, Body::from_stream(stream)).into_response();
    response.headers_mut().extend(headers);
    response
}

fn insert_header(headers: &mut HeaderMap, name: &'static str, value: impl Into<String>) {
    if let Ok(value) = HeaderValue::from_str(&value.into()) {
        headers.insert(HeaderName::from_static(name), value);
    }
}

fn transaction_from_sync_bundle(
    bundle: &RegistrySyncBundle,
    idempotency_key: Option<String>,
    reason: String,
) -> Result<RegistryTransaction, ApiError> {
    let mut mutations = Vec::new();
    let mut ref_updates = Vec::new();
    for blob in &bundle.blobs {
        mutations.push(registry_mutation(
            Some(&bundle.repository_id),
            "blob",
            &blob_id(&blob.blob.hash),
            &blob.blob,
        )?);
    }
    for snapshot in &bundle.snapshots {
        mutations.push(registry_mutation(
            Some(&snapshot.repository_id),
            "snapshot",
            snapshot.id.as_str(),
            snapshot,
        )?);
    }
    for reference in &bundle.refs {
        ref_updates.push(RefCompareAndSwap {
            repository_id: reference.repository_id.clone(),
            name: reference.name.clone(),
            expected_target: None,
            next_ref: serde_json::to_value(reference).map_err(|error| {
                ApiError::internal(format!("failed to encode ref update: {error}"))
            })?,
        });
    }
    for changeset in &bundle.changesets {
        mutations.push(registry_mutation(
            Some(&changeset.repository_id),
            "changeset",
            changeset.id.as_str(),
            changeset,
        )?);
    }
    for proposal in &bundle.proposals {
        mutations.push(registry_mutation(
            Some(&proposal.repository_id),
            "proposal",
            proposal.id.as_str(),
            proposal,
        )?);
    }
    for operation in &bundle.operations {
        mutations.push(registry_mutation(
            Some(&operation.repository_id),
            "operation",
            operation.id.as_str(),
            operation,
        )?);
    }
    for record in &bundle.git_migration_records {
        mutations.push(registry_mutation(
            Some(&record.repository_id),
            "git_migration_record",
            record.id.as_str(),
            record,
        )?);
    }
    for variable in &bundle.environment_variables {
        mutations.push(registry_mutation(
            Some(&variable.repository_id),
            "environment_variable",
            variable.id.as_str(),
            variable,
        )?);
    }
    for version in &bundle.environment_variable_versions {
        mutations.push(registry_mutation(
            Some(&version.repository_id),
            "environment_variable_version",
            version.id.as_str(),
            version,
        )?);
    }
    for environment in &bundle.environments {
        mutations.push(registry_mutation(
            Some(&environment.repository_id),
            "environment",
            environment.id.as_str(),
            environment,
        )?);
    }
    Ok(RegistryTransaction {
        id: format!("tx_sync_{}_{}", bundle.repository_id, now_unix_ms()),
        repository_id: Some(bundle.repository_id.clone()),
        idempotency_key,
        mutations,
        ref_updates,
        audit: RegistryMutationAudit {
            actor: None,
            action: "sync.commit".to_string(),
            reason: Some(reason),
            created_at_unix_ms: now_unix_ms(),
        },
    })
}

fn apply_sync_bundle_to_registry(registry: &mut InMemoryRegistry, bundle: &RegistrySyncBundle) {
    for blob in &bundle.blobs {
        registry.blobs.insert(
            blob.blob.hash.clone(),
            (blob.blob.clone(), blob.bytes.clone()),
        );
    }
    for snapshot in &bundle.snapshots {
        registry
            .snapshots
            .insert(snapshot.id.clone(), snapshot.clone());
    }
    for reference in &bundle.refs {
        registry.refs.insert(
            (reference.repository_id.clone(), reference.name.clone()),
            reference.clone(),
        );
    }
    for changeset in &bundle.changesets {
        registry
            .changesets
            .insert(changeset.id.clone(), changeset.clone());
    }
    for proposal in &bundle.proposals {
        registry
            .proposals
            .insert(proposal.id.clone(), proposal.clone());
    }
    for operation in &bundle.operations {
        registry
            .operations
            .insert(operation.id.clone(), operation.clone());
    }
    for record in &bundle.git_migration_records {
        registry
            .git_migration_records
            .insert(record.id.clone(), record.clone());
    }
    for variable in &bundle.environment_variables {
        registry
            .environment_variables
            .insert(variable.id.clone(), variable.clone());
    }
    for version in &bundle.environment_variable_versions {
        registry
            .environment_variable_versions
            .insert(version.id.clone(), version.clone());
    }
    for environment in &bundle.environments {
        registry
            .environments
            .insert(environment.id.clone(), environment.clone());
    }
}

const BLOB_PERSIST_CONCURRENCY: usize = 32;
const BLOB_FETCH_CONCURRENCY: usize = 64;

/// Resolves each blob's bytes (from the in-memory cache, or the object
/// store when not cached) concurrently in bounded batches. `get_sync_bundle`
/// used to await `blob_store.get()` one blob at a time in a plain `for`
/// loop, which is a sequential round trip per blob to the object store —
/// fine for a handful of blobs, but a full-bundle pull/clone of a
/// thousand-plus-blob repository blew past the gateway timeout the same way
/// the push-side N+1 (see `persist_bundle_blobs_to_store`) once did.
async fn fetch_bundle_blobs_from_store(
    state: &AppState,
    cached_blobs: Vec<(ContentBlob, Vec<u8>)>,
) -> Result<Vec<RegistryBlobRecord>, ApiError> {
    let mut blobs = Vec::with_capacity(cached_blobs.len());
    for chunk in cached_blobs.chunks(BLOB_FETCH_CONCURRENCY) {
        let fetched = futures::future::try_join_all(
            chunk
                .iter()
                .map(|(blob, cached_bytes)| fetch_one_bundle_blob(state, blob, cached_bytes)),
        )
        .await?;
        blobs.extend(fetched);
    }
    Ok(blobs)
}

async fn fetch_one_bundle_blob(
    state: &AppState,
    blob: &ContentBlob,
    cached_bytes: &[u8],
) -> Result<RegistryBlobRecord, ApiError> {
    if blob.size_bytes > MAX_IN_MEMORY_BLOB_BYTES {
        return Ok(RegistryBlobRecord {
            blob: blob.clone(),
            bytes: Vec::new(),
        });
    }
    let bytes = if cached_bytes.is_empty() {
        if let Some(blob_store) = &state.blob_store {
            blob_store
                .get(&blob.hash)
                .await
                .map_err(storage_api_error)?
        } else {
            Vec::new()
        }
    } else {
        cached_bytes.to_vec()
    };
    Ok(RegistryBlobRecord {
        blob: blob.clone(),
        bytes,
    })
}

async fn persist_bundle_blobs_to_store(
    state: &AppState,
    bundle: &RegistrySyncBundle,
    verify_empty_blobs: bool,
) -> Result<(), ApiError> {
    let Some(blob_store) = &state.blob_store else {
        return Ok(());
    };
    for chunk in bundle.blobs.chunks(BLOB_PERSIST_CONCURRENCY) {
        futures::future::try_join_all(
            chunk.iter().map(|record| {
                persist_blob_to_store(blob_store.as_ref(), record, verify_empty_blobs)
            }),
        )
        .await?;
    }
    Ok(())
}

async fn persist_blob_to_store(
    blob_store: &dyn BlobStore,
    record: &RegistryBlobRecord,
    verify_empty_blobs: bool,
) -> Result<(), ApiError> {
    if record.bytes.is_empty() {
        if !verify_empty_blobs {
            return Ok(());
        }
        if blob_store
            .exists(&record.blob.hash)
            .await
            .map_err(storage_api_error)?
        {
            return Ok(());
        }
        return Err(ApiError::bad_request(format!(
            "sync bundle is missing bytes for blob {}",
            record.blob.hash.digest
        )));
    }
    let computed = ContentHash::sha256(&record.bytes);
    if computed != record.blob.hash {
        return Err(ApiError::bad_request(format!(
            "sync bundle blob checksum mismatch for {}",
            record.blob.hash.digest
        )));
    }
    if blob_store
        .exists(&record.blob.hash)
        .await
        .map_err(storage_api_error)?
    {
        return Ok(());
    }
    blob_store
        .put(&record.blob.hash, &record.bytes)
        .await
        .map_err(|error| {
            ApiError::internal(format!(
                "failed to stage blob before metadata commit: {error}"
            ))
        })
}

fn registry_mutation<T: Serialize>(
    repository_id: Option<&RepositoryId>,
    kind: &str,
    id: &str,
    value: &T,
) -> Result<RegistryMutation, ApiError> {
    Ok(RegistryMutation {
        repository_id: repository_id.cloned(),
        kind: kind.to_string(),
        id: id.to_string(),
        value: serde_json::to_value(value)
            .map_err(|error| ApiError::internal(format!("failed to encode {kind}: {error}")))?,
    })
}

async fn ensure_open_sync_session(
    state: &AppState,
    repository_id: &RepositoryId,
    session_id: &SyncSessionId,
) -> Result<(), ApiError> {
    let session = {
        let memory_session = state
            .registry
            .read()
            .map_err(|_| ApiError::internal("registry lock poisoned"))?
            .sync_sessions
            .get(session_id)
            .cloned();
        if let Some(session) = memory_session {
            session
        } else {
            let Some(session) = durable_get_resource::<SyncSession>(
                state,
                Some(repository_id),
                "sync_session",
                session_id.as_str(),
            )
            .await?
            else {
                return Err(ApiError::not_found("sync session not found"));
            };
            state
                .registry
                .write()
                .map_err(|_| ApiError::internal("registry lock poisoned"))?
                .sync_sessions
                .insert(session.id.clone(), session.clone());
            session
        }
    };
    if &session.repository_id != repository_id {
        return Err(ApiError::bad_request("sync session repository mismatch"));
    }
    if session.lease_expires_at_unix_ms <= now_unix_ms() {
        return Err(ApiError::bad_request("sync session lease is expired"));
    }
    match session.state {
        SyncSessionState::Open | SyncSessionState::Uploading | SyncSessionState::Validated => {
            Ok(())
        }
        SyncSessionState::Completed
        | SyncSessionState::Failed
        | SyncSessionState::Aborted
        | SyncSessionState::Expired => Err(ApiError::bad_request("sync session is closed")),
    }
}

async fn cleanup_expired_sync_sessions(state: &AppState) -> Result<(), ApiError> {
    let now = now_unix_ms();
    let expired = {
        let mut registry = state
            .registry
            .write()
            .map_err(|_| ApiError::internal("registry lock poisoned"))?;
        let expired = registry
            .sync_sessions
            .iter_mut()
            .filter_map(|(id, session)| {
                if session.lease_expires_at_unix_ms <= now
                    && matches!(
                        session.state,
                        SyncSessionState::Open
                            | SyncSessionState::Uploading
                            | SyncSessionState::Validated
                    )
                {
                    session.state = SyncSessionState::Expired;
                    Some((id.clone(), session.clone()))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        registry
            .sync_chunks
            .retain(|(session_id, _), _| !expired.iter().any(|(id, _)| id == session_id));
        expired
    };
    for (session_id, session) in expired {
        persist_sync_session_state(state, &session).await?;
        cleanup_sync_artifacts(state, &session.repository_id, &session_id).await?;
    }
    Ok(())
}

fn create_server_auth_token(
    repository_id: RepositoryId,
    request: CreateAuthTokenRequest,
) -> Result<CreateAuthTokenResponse, ApiError> {
    let name = request.name.trim();
    if name.is_empty() {
        return Err(ApiError::bad_request("auth token name is required"));
    }
    validate_token_scopes(&request.scopes)?;
    let now = now_unix_ms();
    let expires_at_unix_ms = bounded_token_expiry(request.expires_at_unix_ms, now)?;
    let token_id = AuthTokenId::generated();
    let raw_token = generate_raw_auth_token(&token_id);
    let token = AuthToken {
        id: token_id,
        repository_id: Some(repository_id),
        org_id: request.org_id,
        actor: request.actor,
        kind: request.kind,
        name: name.to_string(),
        token_hash: ContentHash::sha256(raw_token.as_bytes()).digest,
        scopes: request.scopes,
        expires_at_unix_ms: Some(expires_at_unix_ms),
        revoked_at_unix_ms: None,
    };
    Ok(CreateAuthTokenResponse { token, raw_token })
}

fn validate_token_scopes(scopes: &[PolicyAction]) -> Result<(), ApiError> {
    if scopes.is_empty() {
        return Err(ApiError::bad_request(
            "auth token must include at least one scope",
        ));
    }
    if scopes.contains(&PolicyAction::ManageAuth) {
        return Err(ApiError::bad_request(
            "self-hosted registry API tokens cannot grant ManageAuth",
        ));
    }
    Ok(())
}

fn bounded_token_expiry(requested: Option<u64>, now: u64) -> Result<u64, ApiError> {
    let default_expiry = now.saturating_add(DEFAULT_AUTH_TOKEN_TTL_MS);
    let requested = requested.unwrap_or(default_expiry);
    if requested <= now {
        return Err(ApiError::bad_request(
            "auth token expiry must be in the future",
        ));
    }
    let max_expiry = now.saturating_add(MAX_AUTH_TOKEN_TTL_MS);
    if requested > max_expiry {
        return Err(ApiError::bad_request(
            "auth token expiry exceeds the maximum allowed TTL",
        ));
    }
    Ok(requested)
}

fn generate_raw_auth_token(token_id: &AuthTokenId) -> String {
    format!(
        "neb_{}_{}",
        token_id.as_str(),
        AuthTokenId::generated().as_str()
    )
}

fn storage_api_error(error: NebulaError) -> ApiError {
    match error {
        NebulaError::NotFound(message) => ApiError::not_found(message),
        NebulaError::PolicyBlocked(message) => ApiError {
            status: StatusCode::FORBIDDEN,
            message,
        },
        NebulaError::Storage(message) | NebulaError::InvalidOperation(message) => {
            ApiError::internal(message)
        }
    }
}

async fn ensure_environment(
    state: &AppState,
    repository_id: &RepositoryId,
    environment_id: &EnvironmentId,
) -> Result<Environment, ApiError> {
    if let Some(environment) = durable_get_resource::<Environment>(
        state,
        Some(repository_id),
        "environment",
        environment_id.as_str(),
    )
    .await?
    {
        return Ok(environment);
    }
    state
        .registry
        .read()
        .map_err(|_| ApiError::internal("registry lock poisoned"))?
        .environments
        .get(environment_id)
        .filter(|environment| &environment.repository_id == repository_id)
        .cloned()
        .ok_or_else(|| ApiError::not_found("environment not found"))
}

fn normalize_variable_key(raw: &str) -> Result<String, ApiError> {
    let key = raw.trim();
    if key.is_empty() {
        return Err(ApiError::bad_request("variable key is required"));
    }
    if !key
        .chars()
        .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_')
    {
        return Err(ApiError::bad_request(
            "variable key must use uppercase letters, digits, and underscores",
        ));
    }
    Ok(key.to_string())
}

fn default_variable_sensitivity(
    key: &str,
    environment_kind: &EnvironmentKind,
) -> VariableSensitivity {
    if matches!(
        environment_kind,
        EnvironmentKind::Production | EnvironmentKind::Staging
    ) || likely_secret_key(key)
    {
        VariableSensitivity::Sensitive
    } else {
        VariableSensitivity::Encrypted
    }
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

fn default_variable_value_kind(
    sensitivity: &VariableSensitivity,
    reference: Option<&VariableReference>,
) -> VariableValueKind {
    if reference.is_some() {
        VariableValueKind::Reference
    } else if sensitivity.is_write_only() {
        VariableValueKind::Secret
    } else {
        VariableValueKind::Literal
    }
}

fn default_secret_storage_mode(
    sensitivity: &VariableSensitivity,
    value_kind: &VariableValueKind,
) -> VariableSecretStorageMode {
    if matches!(
        value_kind,
        VariableValueKind::Reference | VariableValueKind::ProviderRef
    ) {
        VariableSecretStorageMode::ExternalProvider
    } else if matches!(sensitivity, VariableSensitivity::Public) {
        VariableSecretStorageMode::MetadataOnly
    } else {
        VariableSecretStorageMode::RegistryEncrypted
    }
}

#[allow(clippy::too_many_arguments)]
async fn create_environment_variable_version(
    state: &AppState,
    repository_id: &RepositoryId,
    variable_id: &EnvironmentVariableId,
    key: &str,
    value_kind: &VariableValueKind,
    sensitivity: &VariableSensitivity,
    storage_mode: &VariableSecretStorageMode,
    value: &str,
    actor: Actor,
) -> Result<EnvironmentVariableVersion, ApiError> {
    let now = now_unix_ms();
    let id = EnvironmentVariableVersionId::generated();
    let fingerprint = Some(secret_fingerprint(state, key, value)?);
    let value_digest = Some(ContentHash::sha256(value.as_bytes()).digest);
    let mut version = EnvironmentVariableVersion {
        id,
        repository_id: repository_id.clone(),
        variable_id: variable_id.clone(),
        key: key.to_string(),
        sensitivity: sensitivity.clone(),
        value_kind: value_kind.clone(),
        storage_mode: storage_mode.clone(),
        plaintext_value: None,
        ciphertext: None,
        content_hash: None,
        encryption_key_id: None,
        wrapped_data_key: None,
        nonce: None,
        fingerprint,
        value_digest,
        redaction_tokens: if sensitivity.is_write_only() {
            redaction_values(value)
        } else {
            Vec::new()
        },
        created_by: Some(actor),
        created_at_unix_ms: now,
        last_injected_at_unix_ms: None,
        last_used_by_deploy_id: None,
    };
    if matches!(sensitivity, VariableSensitivity::Public)
        && matches!(storage_mode, VariableSecretStorageMode::MetadataOnly)
    {
        version.plaintext_value = Some(value.to_string());
        return Ok(version);
    }
    let encrypted = encrypt_secret_value(state, &version.id, key, value)?;
    version.ciphertext = Some(encrypted.ciphertext.clone());
    version.encryption_key_id = Some(encrypted.encryption_key_id);
    version.wrapped_data_key = Some(encrypted.wrapped_data_key);
    version.nonce = Some(encrypted.nonce);
    if matches!(storage_mode, VariableSecretStorageMode::BlobBackedEncrypted) {
        let bytes = encrypted.ciphertext.into_bytes();
        let blob = ContentBlob::from_bytes(
            &bytes,
            Some("application/vnd.nebula.secret+ciphertext".to_string()),
            BlobVisibility::Encrypted {
                key_envelope_id: version
                    .encryption_key_id
                    .clone()
                    .unwrap_or_else(|| "registry-local".to_string()),
            },
        );
        if let Some(store) = &state.blob_store {
            store.put(&blob.hash, &bytes).await.map_err(|error| {
                ApiError::internal(format!("failed to persist secret blob: {error}"))
            })?;
        }
        durable_put_resource(
            state,
            Some(repository_id),
            "blob",
            &blob_id(&blob.hash),
            &blob,
        )
        .await?;
        state
            .registry
            .write()
            .map_err(|_| ApiError::internal("registry lock poisoned"))?
            .blobs
            .insert(blob.hash.clone(), (blob.clone(), bytes));
        version.content_hash = Some(blob.hash);
    }
    Ok(version)
}

#[derive(Clone, Debug)]
struct EncryptedSecretValue {
    ciphertext: String,
    encryption_key_id: String,
    wrapped_data_key: String,
    nonce: String,
}

fn encrypt_secret_value(
    state: &AppState,
    version_id: &EnvironmentVariableVersionId,
    key: &str,
    value: &str,
) -> Result<EncryptedSecretValue, ApiError> {
    let master = registry_secret_key(state);
    let data_key =
        ContentHash::sha256(format!("{}:{key}:data-key", version_id.as_str()).as_bytes()).digest;
    let data_key_bytes = hex::decode(&data_key)
        .map_err(|_| ApiError::internal("failed to derive secret data key"))?;
    let nonce_digest =
        ContentHash::sha256(format!("{}:{key}:nonce", version_id.as_str()).as_bytes()).digest;
    let nonce_bytes = hex::decode(&nonce_digest[..24])
        .map_err(|_| ApiError::internal("failed to derive secret nonce"))?;
    let cipher = Aes256Gcm::new_from_slice(&data_key_bytes)
        .map_err(|_| ApiError::internal("failed to initialize secret cipher"))?;
    let nonce = Nonce::try_from(nonce_bytes.as_slice())
        .map_err(|_| ApiError::internal("failed to derive secret nonce"))?;
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: value.as_bytes(),
                aad: key.as_bytes(),
            },
        )
        .map_err(|_| ApiError::internal("failed to encrypt secret value"))?;
    Ok(EncryptedSecretValue {
        ciphertext: hex::encode(ciphertext),
        encryption_key_id: "registry-local-v1".to_string(),
        wrapped_data_key: wrap_data_key(&master, &data_key_bytes)?,
        nonce: hex::encode(nonce_bytes),
    })
}

fn decrypt_environment_variable_value(
    state: &AppState,
    version: &EnvironmentVariableVersion,
) -> Result<String, ApiError> {
    if let Some(value) = &version.plaintext_value {
        return Ok(value.clone());
    }
    let ciphertext = version
        .ciphertext
        .as_ref()
        .ok_or_else(|| ApiError::not_found("environment variable value is encrypted externally"))?;
    let nonce = version
        .nonce
        .as_ref()
        .ok_or_else(|| ApiError::internal("encrypted value is missing nonce"))?;
    let wrapped_data_key = version
        .wrapped_data_key
        .as_ref()
        .ok_or_else(|| ApiError::internal("encrypted value is missing wrapped data key"))?;
    let master = registry_secret_key(state);
    let data_key = unwrap_data_key(&master, wrapped_data_key)?;
    let ciphertext = hex::decode(ciphertext)
        .map_err(|_| ApiError::internal("encrypted value has invalid ciphertext"))?;
    let nonce =
        hex::decode(nonce).map_err(|_| ApiError::internal("encrypted value has invalid nonce"))?;
    let cipher = Aes256Gcm::new_from_slice(&data_key)
        .map_err(|_| ApiError::internal("failed to initialize secret cipher"))?;
    let nonce = Nonce::try_from(nonce.as_slice())
        .map_err(|_| ApiError::internal("encrypted value has invalid nonce"))?;
    let plaintext = cipher
        .decrypt(
            &nonce,
            Payload {
                msg: &ciphertext,
                aad: version.key.as_bytes(),
            },
        )
        .map_err(|_| ApiError::internal("failed to decrypt secret value"))?;
    String::from_utf8(plaintext).map_err(|_| ApiError::internal("secret value is not valid UTF-8"))
}

fn registry_secret_key(state: &AppState) -> Vec<u8> {
    let raw = state
        .secret_encryption_key
        .as_deref()
        .or(state.astracollab_deploy_signing_secret.as_deref())
        .or(state.telemetry_webhook_secret.as_deref())
        .unwrap_or("nebula-registry-local-development-secret-encryption-key");
    ContentHash::sha256(raw.as_bytes())
        .digest
        .as_bytes()
        .chunks(2)
        .filter_map(|chunk| std::str::from_utf8(chunk).ok())
        .filter_map(|hex| u8::from_str_radix(hex, 16).ok())
        .collect()
}

fn wrap_data_key(master: &[u8], data_key: &[u8]) -> Result<String, ApiError> {
    let cipher = Aes256Gcm::new_from_slice(master)
        .map_err(|_| ApiError::internal("failed to initialize wrapping cipher"))?;
    let nonce = Nonce::from([0_u8; 12]);
    let wrapped = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: data_key,
                aad: b"nebula-env-data-key",
            },
        )
        .map_err(|_| ApiError::internal("failed to wrap secret data key"))?;
    Ok(hex::encode(wrapped))
}

fn unwrap_data_key(master: &[u8], wrapped_data_key: &str) -> Result<Vec<u8>, ApiError> {
    let cipher = Aes256Gcm::new_from_slice(master)
        .map_err(|_| ApiError::internal("failed to initialize wrapping cipher"))?;
    let nonce = Nonce::from([0_u8; 12]);
    let wrapped = hex::decode(wrapped_data_key)
        .map_err(|_| ApiError::internal("invalid wrapped secret data key"))?;
    cipher
        .decrypt(
            &nonce,
            Payload {
                msg: &wrapped,
                aad: b"nebula-env-data-key",
            },
        )
        .map_err(|_| ApiError::internal("failed to unwrap secret data key"))
}

type HmacSha256 = Hmac<Sha256>;

fn secret_fingerprint(state: &AppState, key: &str, value: &str) -> Result<String, ApiError> {
    let mut mac = HmacSha256::new_from_slice(&registry_secret_key(state))
        .map_err(|_| ApiError::internal("failed to initialize HMAC"))?;
    mac.update(key.as_bytes());
    mac.update(b"\0");
    mac.update(value.as_bytes());
    Ok(hex::encode(mac.finalize().into_bytes()))
}

fn variable_version_view(
    version: &EnvironmentVariableVersion,
    include_plaintext: bool,
) -> EnvironmentVariableVersionView {
    EnvironmentVariableVersionView {
        id: version.id.clone(),
        variable_id: version.variable_id.clone(),
        key: version.key.clone(),
        sensitivity: version.sensitivity.clone(),
        value_kind: version.value_kind.clone(),
        storage_mode: version.storage_mode.clone(),
        masked_value: Some(masked_value(
            &version.sensitivity,
            version.fingerprint.as_deref(),
        )),
        plaintext_value: include_plaintext
            .then(|| version.plaintext_value.clone())
            .flatten(),
        content_hash: version.content_hash.clone(),
        encryption_key_id: version.encryption_key_id.clone(),
        wrapped_data_key: version.wrapped_data_key.clone(),
        nonce: version.nonce.clone(),
        fingerprint: version.fingerprint.clone(),
        value_digest: version.value_digest.clone(),
        created_at_unix_ms: version.created_at_unix_ms,
    }
}

fn masked_value(sensitivity: &VariableSensitivity, fingerprint: Option<&str>) -> String {
    match sensitivity {
        VariableSensitivity::Public => "[public]".to_string(),
        VariableSensitivity::Encrypted => fingerprint_suffix(fingerprint, "[encrypted]"),
        VariableSensitivity::Sensitive => fingerprint_suffix(fingerprint, "[sensitive]"),
        VariableSensitivity::Sealed => fingerprint_suffix(fingerprint, "[sealed]"),
    }
}

fn fingerprint_suffix(fingerprint: Option<&str>, label: &str) -> String {
    let Some(fingerprint) = fingerprint else {
        return label.to_string();
    };
    let suffix = fingerprint
        .get(fingerprint.len().saturating_sub(8)..)
        .unwrap_or(fingerprint);
    format!("{label} ...{suffix}")
}

fn redaction_values(value: &str) -> Vec<String> {
    if value.len() < 4 || matches!(value, "true" | "false" | "TRUE" | "FALSE") {
        return Vec::new();
    }
    let mut values = BTreeSet::new();
    values.insert(value.to_string());
    values.insert(hex::encode(value.as_bytes()));
    values.insert(value.replace('\n', "\\n"));
    values.insert(value.replace('\n', ""));
    values.into_iter().collect()
}

pub(crate) fn blob_id(hash: &ContentHash) -> String {
    format!("{}:{}", hash.algorithm, hash.digest)
}

pub(crate) fn ref_id(repository_id: &RepositoryId, name: &str) -> String {
    format!("{}_{}", repository_id.as_str(), name)
}

/// Durable resource id for an OCI manifest.
///
/// Manifests are addressed per repository, so the same digest legitimately
/// exists in several repositories at once. The id has to carry the repository
/// as well, otherwise a push to the second repository overwrites the first
/// record and hydration silently drops one repository's copy of the manifest,
/// which then serves MANIFEST_UNKNOWN forever. `@` cannot appear in a
/// repository name accepted by `validate_oci_repository_name`, so the pair is
/// unambiguous.
pub(crate) fn oci_manifest_id(repository: &str, digest: &str) -> String {
    format!("{repository}@{digest}")
}

fn idempotency_key(headers: &HeaderMap) -> Option<String> {
    headers
        .get("idempotency-key")
        .or_else(|| headers.get("x-idempotency-key"))
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or_default()
}

fn sync_temp_path(session_id: &SyncSessionId, hash: &ContentHash) -> PathBuf {
    std::env::temp_dir()
        .join("nebula-sync")
        .join(session_id.as_str())
        .join(format!("{}_{}", hash.algorithm, hash.digest))
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;
    use axum::{
        body::{Body, to_bytes},
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    #[test]
    fn corrupt_persistence_file_fails_closed() {
        let dir = std::env::temp_dir().join(format!("nebula-corrupt-{}", now_unix_ms()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("registry.json");
        fs::write(&path, "{ not valid json").unwrap();
        match load_registry_from_persistence(Some(&path)) {
            Ok(_) => panic!("expected corrupt persistence load to fail"),
            Err(error) => assert!(
                error.contains("failed to load registry persistence"),
                "{error}"
            ),
        }
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn atomic_save_round_trips_and_leaves_no_tmp() {
        let dir = std::env::temp_dir().join(format!("nebula-atomic-{}", now_unix_ms()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("registry.json");
        let mut registry = InMemoryRegistry::default();
        registry.repositories.insert(
            RepositoryId::new("repo_atomic"),
            RepositoryRecord {
                id: RepositoryId::new("repo_atomic"),
                name: "acme/app".to_string(),
                org_id: None,
            },
        );
        registry.save_to_path(&path).unwrap();
        assert!(path.exists());
        let reloaded = InMemoryRegistry::load_from_path(&path).unwrap();
        assert!(reloaded.repositories.contains_key(&RepositoryId::new("repo_atomic")));
        let tmp_count = fs::read_dir(&dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".nebula-registry-tmp-")
            })
            .count();
        assert_eq!(tmp_count, 0);
        let _ = fs::remove_dir_all(dir);
    }

    struct AllowAllAuthProvider;

    #[async_trait::async_trait]
    impl RegistryAuthProvider for AllowAllAuthProvider {
        async fn verify_bearer(
            &self,
            _raw_token: &str,
            route_repository_id: Option<RepositoryId>,
        ) -> Result<VerifiedClaims, String> {
            Ok(VerifiedClaims {
                actor: Actor::User("user_1".to_string()),
                org_id: None,
                repository_id: route_repository_id,
                token_id: None,
                scopes: vec![
                    PolicyAction::ReadBlob,
                    PolicyAction::ReadPath,
                    PolicyAction::PullImage,
                    PolicyAction::PushImage,
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
                    PolicyAction::ManageVariables,
                    PolicyAction::ReadVariableMetadata,
                    PolicyAction::ReadEncryptedVariable,
                    PolicyAction::ReadVariableValue,
                    PolicyAction::InjectVariable,
                    PolicyAction::RevealVariable,
                    PolicyAction::SaveSecret,
                    PolicyAction::PushSecret,
                    PolicyAction::ExportSecret,
                    PolicyAction::UseWorkspaceForDeploy,
                    PolicyAction::MutateDeployVariables,
                    PolicyAction::ManageVariablePolicy,
                ],
            })
        }
    }

    struct TenantFixtureAuthProvider;

    #[async_trait::async_trait]
    impl RegistryAuthProvider for TenantFixtureAuthProvider {
        async fn verify_bearer(
            &self,
            raw_token: &str,
            route_repository_id: Option<RepositoryId>,
        ) -> Result<VerifiedClaims, String> {
            match raw_token {
                "setup" => Ok(VerifiedClaims {
                    actor: Actor::User("owner".to_string()),
                    org_id: None,
                    repository_id: route_repository_id,
                    token_id: None,
                    scopes: vec![PolicyAction::ManageAuth, PolicyAction::ReadPath],
                }),
                "org-a-read" => Ok(VerifiedClaims {
                    actor: Actor::User("alice".to_string()),
                    org_id: Some("org_a".to_string()),
                    repository_id: route_repository_id,
                    token_id: None,
                    scopes: vec![PolicyAction::ReadBlob],
                }),
                "org-a-admin-unbound" => Ok(VerifiedClaims {
                    actor: Actor::User("alice".to_string()),
                    org_id: Some("org_a".to_string()),
                    repository_id: None,
                    token_id: None,
                    scopes: vec![PolicyAction::ManageAuth, PolicyAction::ReadBlob],
                }),
                "org-a-no-read" => Ok(VerifiedClaims {
                    actor: Actor::User("alice".to_string()),
                    org_id: Some("org_a".to_string()),
                    repository_id: route_repository_id,
                    token_id: None,
                    scopes: vec![PolicyAction::SyncObjects],
                }),
                _ => Err("invalid fixture token".to_string()),
            }
        }
    }

    #[tokio::test]
    async fn registry_can_create_repo_and_emit_schema() {
        let app = router(RegistryConfig::default());
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/galaxies")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"name":"acme/app"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let repo: RepositoryRecord = serde_json::from_slice(&body).unwrap();

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/v1/galaxies/{}", repo.id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/schema")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let schema: Value = serde_json::from_slice(&body).unwrap();
        assert!(schema.get("CreateRepositoryRequest").is_some());
        assert!(schema.get("ProjectionManifest").is_some());
    }

    #[tokio::test]
    async fn registry_masks_sensitive_variables_and_injects_authorized_bundle() {
        let app = router(RegistryConfig {
            secret_encryption_key: Some("test-secret-encryption-key-at-least-32-bytes".to_string()),
            ..Default::default()
        });
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/galaxies")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"name":"acme/env-app"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let repo: RepositoryRecord = serde_json::from_slice(&body).unwrap();
        let env = Environment {
            id: EnvironmentId::new("env_production"),
            repository_id: repo.id.clone(),
            name: "production".to_string(),
            kind: EnvironmentKind::Production,
        };
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/v1/galaxies/{}/environments", repo.id))
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&env).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!(
                        "/v1/galaxies/{}/environments/{}/variables",
                        repo.id, env.id
                    ))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{
                            "key":"DATABASE_URL",
                            "value":"postgres://user:pass@example/db",
                            "availability":["Build","Runtime"],
                            "sensitivity":"Sensitive"
                        }"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/v1/galaxies/{}/environments/{}/variables",
                        repo.id, env.id
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let listed: ListEnvironmentVariablesResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(listed.variables.len(), 1);
        assert!(
            listed.variables[0]
                .current_version
                .as_ref()
                .unwrap()
                .plaintext_value
                .is_none()
        );
        assert!(
            listed.variables[0]
                .current_version
                .as_ref()
                .unwrap()
                .masked_value
                .as_deref()
                .unwrap()
                .contains("[sensitive]")
        );

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!(
                        "/v1/galaxies/{}/environments/{}/variables/inject",
                        repo.id, env.id
                    ))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{
                            "actor":{"Integration":"horizon"},
                            "service_id":"workspace/project/production/client",
                            "availability":"Build"
                        }"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let injected: InjectEnvironmentVariablesResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(injected.variables[0].key, "DATABASE_URL");
        assert_eq!(
            injected.variables[0].value,
            "postgres://user:pass@example/db"
        );
        assert!(injected.redaction_tokens.contains_key("DATABASE_URL"));
    }

    #[tokio::test]
    async fn external_auth_provider_disables_nebula_owned_auth_token_creation() {
        let config = RegistryConfig {
            auth_required: true,
            auth_token_authority: AuthTokenAuthority::AstracollabHosted,
            ..Default::default()
        };
        let app = router_async_with_auth_provider(config, Some(Arc::new(AllowAllAuthProvider)))
            .await
            .unwrap();

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/galaxies")
                    .header("authorization", "Bearer valid")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"name":"acme/app"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let repo: RepositoryRecord = serde_json::from_slice(&body).unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/v1/galaxies/{}/auth-tokens", repo.id))
                    .header("authorization", "Bearer valid")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{
                            "name":"legacy token",
                            "actor":{"User":"user_1"},
                            "kind":"User",
                            "scopes":["ReadBlob"]
                        }"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn tenant_claims_scopes_and_audits_protect_repository_boundaries() {
        let state_path =
            std::env::temp_dir().join(format!("nebula-tenant-proof-{}.json", now_unix_ms()));
        let config = RegistryConfig {
            auth_required: true,
            auth_token_authority: AuthTokenAuthority::AstracollabHosted,
            persistence_path: Some(state_path.clone()),
            ..Default::default()
        };
        let app =
            router_async_with_auth_provider(config, Some(Arc::new(TenantFixtureAuthProvider)))
                .await
                .unwrap();

        let repo_a = create_fixture_repository(&app, "org-a/repo-a", "org_a").await;
        let repo_b = create_fixture_repository(&app, "org-b/repo-b", "org_b").await;
        put_fixture_read_policy(&app, &repo_a).await;

        let allowed = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/v1/galaxies/{repo_a}"))
                    .header("authorization", "Bearer org-a-read")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(allowed.status(), StatusCode::OK);

        let wrong_org = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/v1/galaxies/{repo_b}"))
                    .header("authorization", "Bearer org-a-admin-unbound")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(wrong_org.status(), StatusCode::FORBIDDEN);

        let missing_scope = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/v1/galaxies/{repo_a}"))
                    .header("authorization", "Bearer org-a-no-read")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(missing_scope.status(), StatusCode::FORBIDDEN);

        let persisted: PersistedRegistry =
            serde_json::from_str(&std::fs::read_to_string(&state_path).unwrap()).unwrap();
        let audits = persisted.authorization_audits;
        assert!(audits.iter().any(|audit| {
            audit.get("repository_id") == Some(&json!(repo_a.as_str()))
                && audit.get("decision") == Some(&json!("Allow"))
                && audit.get("reason").and_then(Value::as_str).is_some()
        }));
        assert!(audits.iter().any(|audit| {
            audit.get("repository_id") == Some(&json!(repo_b.as_str()))
                && audit.get("decision") == Some(&json!("Block"))
                && audit
                    .get("reason")
                    .and_then(Value::as_str)
                    .is_some_and(|reason| reason.contains("organization claim"))
        }));
        assert!(audits.iter().any(|audit| {
            audit.get("repository_id") == Some(&json!(repo_a.as_str()))
                && audit.get("decision") == Some(&json!("Block"))
                && audit
                    .get("reason")
                    .and_then(Value::as_str)
                    .is_some_and(|reason| reason.contains("token scope"))
        }));
        let _ = std::fs::remove_file(state_path);
    }

    #[tokio::test]
    async fn blob_routes_are_backed_by_memory_store() {
        let app = router(RegistryConfig::default());
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/galaxies")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"name":"acme/app"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let repo: RepositoryRecord = serde_json::from_slice(&body).unwrap();

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/v1/galaxies/{}/blobs", repo.id))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"bytes_utf8":"hello","media_type":"text/plain","visibility":"Public"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let created: BlobPutResponse = serde_json::from_slice(&body).unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/v1/galaxies/{}/blobs/{}/{}",
                        repo.id, created.blob.hash.algorithm, created.blob.hash.digest
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn oci_routes_push_and_pull_manifest_and_blob() {
        let app = router(RegistryConfig::default());
        let layer = b"hello layer".to_vec();
        let layer_digest = oci_test_digest(&layer);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v2/acme/app/blobs/uploads/?digest={layer_digest}"))
                    .body(Body::from(layer.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(
            response.headers()["docker-content-digest"]
                .to_str()
                .unwrap(),
            layer_digest
        );

        let manifest = json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": layer_digest,
                "size": layer.len()
            },
            "layers": [
                {
                    "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                    "digest": layer_digest,
                    "size": layer.len()
                }
            ]
        });
        let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
        let manifest_digest = oci_test_digest(&manifest_bytes);
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/v2/acme/app/manifests/latest")
                    .header("content-type", "application/vnd.oci.image.manifest.v1+json")
                    .body(Body::from(manifest_bytes.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(
            response.headers()["docker-content-digest"]
                .to_str()
                .unwrap(),
            manifest_digest
        );

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v2/acme/app/manifests/latest")
                    .header("accept", "application/vnd.oci.image.manifest.v1+json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()["docker-content-digest"]
                .to_str()
                .unwrap(),
            manifest_digest
        );
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(body.as_ref(), manifest_bytes.as_slice());

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v2/acme/app/tags/list?n=1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let tags: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(tags["tags"], json!(["latest"]));

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/v2/acme/app/blobs/{layer_digest}"))
                    .header("range", "bytes=0-4")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(body.as_ref(), b"hello");
    }

    #[tokio::test]
    async fn oci_auth_challenge_and_scopes_are_docker_compatible() {
        let config = RegistryConfig {
            auth_required: true,
            ..Default::default()
        };
        let app = router(config);
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v2/acme/app/tags/list")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(
            response.headers()["www-authenticate"]
                .to_str()
                .unwrap()
                .contains("Basic")
        );

        let repository_id = RepositoryId::new("repo_oci");
        let token_response = create_server_auth_token(
            repository_id.clone(),
            CreateAuthTokenRequest {
                name: "oci push pull".to_string(),
                actor: Actor::Agent("builder".to_string()),
                kind: AuthTokenKind::Agent,
                scopes: vec![PolicyAction::PushImage, PolicyAction::PullImage],
                org_id: None,
                expires_at_unix_ms: None,
            },
        )
        .unwrap();
        let mut registry = InMemoryRegistry::default();
        registry.repositories.insert(
            repository_id.clone(),
            RepositoryRecord {
                id: repository_id,
                name: "acme/app".to_string(),
                org_id: None,
            },
        );
        registry
            .auth_tokens
            .insert(token_response.token.id.clone(), token_response.token);
        let app = router_with_state(
            RegistryConfig {
                auth_required: true,
                ..Default::default()
            },
            registry,
        );
        let layer = b"scoped layer".to_vec();
        let layer_digest = oci_test_digest(&layer);
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v2/acme/app/blobs/uploads/?digest={layer_digest}"))
                    .header(
                        "authorization",
                        format!("Bearer {}", token_response.raw_token),
                    )
                    .body(Body::from(layer))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn astracollab_bootstrap_token_reads_and_writes_but_cannot_manage_auth() {
        let repository_id = RepositoryId::new("repo_astracollab");
        let mut registry = InMemoryRegistry::default();
        registry.repositories.insert(
            repository_id.clone(),
            RepositoryRecord {
                id: repository_id.clone(),
                name: "acme/astracollab".to_string(),
                org_id: None,
            },
        );
        let service_policy = default_astracollab_service_policy(&repository_id);
        registry
            .policies
            .insert(service_policy.id.clone(), service_policy);
        let raw_token = "astracollab-service-test-token";
        let app = router_with_state(
            RegistryConfig {
                auth_required: true,
                bootstrap_auth_tokens: vec![RegistryBootstrapAuthToken {
                    name: "astracollab-dashboard".to_string(),
                    raw_token: raw_token.to_string(),
                    scopes: vec![PolicyAction::ReadBlob, PolicyAction::WriteChangeSet],
                }],
                ..Default::default()
            },
            registry,
        );

        // WriteChangeSet-scoped route (blob PUT) succeeds.
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/v1/galaxies/{repository_id}/blobs"))
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {raw_token}"))
                    .body(Body::from(
                        r#"{"bytes_utf8":"hello","media_type":"text/plain","visibility":"Public"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let created: BlobPutResponse = serde_json::from_slice(&body).unwrap();

        // ReadBlob-scoped route (blob GET) succeeds.
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/v1/galaxies/{}/blobs/{}/{}",
                        repository_id, created.blob.hash.algorithm, created.blob.hash.digest
                    ))
                    .header("authorization", format!("Bearer {raw_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // ManageAuth-scoped route (creating a new galaxy) is rejected.
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/galaxies")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {raw_token}"))
                    .body(Body::from(r#"{"name":"acme/other"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn stored_api_token_is_hash_checked_and_repository_bound() {
        let repository_id = RepositoryId::new("repo_a");
        let raw_token = "nebula_test_token";
        let token = AuthToken {
            id: AuthTokenId::new("tok_a"),
            repository_id: Some(repository_id.clone()),
            org_id: Some("org_a".to_string()),
            actor: Actor::User("alice".to_string()),
            kind: AuthTokenKind::User,
            name: "test".to_string(),
            token_hash: ContentHash::sha256(raw_token.as_bytes()).digest,
            scopes: vec![PolicyAction::ReadBlob],
            expires_at_unix_ms: Some(now_unix_ms() + 60_000),
            revoked_at_unix_ms: None,
        };
        let mut registry = InMemoryRegistry::default();
        registry.repositories.insert(
            repository_id.clone(),
            RepositoryRecord {
                id: repository_id.clone(),
                name: "repo-a".to_string(),
                org_id: Some("org_a".to_string()),
            },
        );
        registry.auth_tokens.insert(token.id.clone(), token);
        let state = AppState {
            registry: Arc::new(RwLock::new(registry)),
            persistence_path: None,
            auth: AuthConfig {
                required: false,
                verifier: None,
                token_authority: AuthTokenAuthority::NebulaSelfHosted,
            },
            external_auth_provider: None,
            external_auth_cache: Arc::new(RwLock::new(BTreeMap::new())),
            durable_store: None,
            blob_store: None,
            object_blob_store: None,
            vector_store: None,
            public_base_url: None,
            astracollab_deploy_url: None,
            astracollab_deploy_signing_secret: None,
            deploy_archive_cache: Arc::new(RwLock::new(BTreeMap::new())),
            telemetry_sinks: vec!["json".to_string(), "prometheus".to_string()],
            telemetry_event_file: None,
            telemetry_webhook_url: None,
            telemetry_webhook_secret: None,
            secret_encryption_key: Some("test-secret-encryption-key-at-least-32-bytes".to_string()),
            http_client: reqwest::Client::new(),
        };

        let verified = verify_stored_api_token(&state, raw_token, Some(&repository_id)).unwrap();
        assert_eq!(verified.repository_id, Some(repository_id.clone()));
        assert_eq!(verified.org_id, Some("org_a".to_string()));
        assert!(
            verify_stored_api_token(&state, raw_token, Some(&RepositoryId::new("repo_b"))).is_err()
        );
    }

    #[test]
    fn server_generated_auth_token_hashes_raw_token_and_bounds_scope() {
        let repository_id = RepositoryId::new("repo_a");
        let response = create_server_auth_token(
            repository_id.clone(),
            CreateAuthTokenRequest {
                name: "agent token".to_string(),
                actor: Actor::Agent("agent_1".to_string()),
                kind: AuthTokenKind::Agent,
                scopes: vec![PolicyAction::ReadBlob, PolicyAction::SyncObjects],
                org_id: Some("org_a".to_string()),
                expires_at_unix_ms: None,
            },
        )
        .unwrap();

        assert!(response.raw_token.starts_with("neb_tok_"));
        assert_eq!(response.token.repository_id, Some(repository_id));
        assert_eq!(
            response.token.token_hash,
            ContentHash::sha256(response.raw_token.as_bytes()).digest
        );
        assert!(response.token.expires_at_unix_ms.is_some());
    }

    fn oci_test_digest(bytes: &[u8]) -> String {
        let hash = ContentHash::sha256(bytes);
        format!("{}:{}", hash.algorithm, hash.digest)
    }

    /// Minimal store that only supports the resource put/list calls hydration
    /// needs, so tests can exercise a real write -> restart -> read round trip.
    #[derive(Default)]
    struct FakeResourceStore {
        resources: std::sync::Mutex<BTreeMap<(String, String), Value>>,
    }

    #[async_trait::async_trait]
    impl RegistryStore for FakeResourceStore {
        async fn put_resource(
            &self,
            _repository_id: Option<&RepositoryId>,
            kind: &str,
            id: &str,
            value: Value,
        ) -> NebulaResult<()> {
            self.resources
                .lock()
                .unwrap()
                .insert((kind.to_string(), id.to_string()), value);
            Ok(())
        }

        async fn list_resources(&self, kind: &str) -> NebulaResult<Vec<Value>> {
            Ok(self
                .resources
                .lock()
                .unwrap()
                .iter()
                .filter(|((stored_kind, _), _)| stored_kind == kind)
                .map(|(_, value)| value.clone())
                .collect())
        }

        async fn put_repository_record(
            &self,
            _repository_id: &RepositoryId,
            _value: Value,
        ) -> NebulaResult<()> {
            unimplemented!("not exercised by these tests")
        }

        async fn get_repository_record(
            &self,
            _repository_id: &RepositoryId,
        ) -> NebulaResult<Value> {
            unimplemented!("not exercised by these tests")
        }

        async fn get_resource(&self, _kind: &str, _id: &str) -> NebulaResult<Value> {
            unimplemented!("not exercised by these tests")
        }

        async fn get_resource_scoped(
            &self,
            _repository_id: Option<&RepositoryId>,
            _kind: &str,
            _id: &str,
        ) -> NebulaResult<Value> {
            unimplemented!("not exercised by these tests")
        }

        async fn list_resources_scoped(
            &self,
            _repository_id: Option<&RepositoryId>,
            _kind: &str,
        ) -> NebulaResult<Vec<Value>> {
            unimplemented!("not exercised by these tests")
        }

        async fn delete_resource(
            &self,
            _repository_id: Option<&RepositoryId>,
            _kind: &str,
            _id: &str,
        ) -> NebulaResult<()> {
            unimplemented!("not exercised by these tests")
        }

        async fn put_resource_idempotent(
            &self,
            _repository_id: Option<&RepositoryId>,
            _kind: &str,
            _id: &str,
            _idempotency_key: &str,
            _value: Value,
        ) -> NebulaResult<Value> {
            unimplemented!("not exercised by these tests")
        }

        async fn compare_and_swap_ref(
            &self,
            _repository_id: &RepositoryId,
            _name: &str,
            _expected_target: Option<Value>,
            _next_ref: Value,
        ) -> NebulaResult<bool> {
            unimplemented!("not exercised by these tests")
        }

        async fn commit_transaction(
            &self,
            _transaction: RegistryTransaction,
        ) -> NebulaResult<RegistryTransactionResult> {
            unimplemented!("not exercised by these tests")
        }
    }

    fn oci_test_manifest(repository: &str, digest: &str) -> OciManifest {
        OciManifest {
            schema_version: OCI_METADATA_SCHEMA_VERSION,
            repository_name: repository.to_string(),
            repository_name_normalized: repository.to_string(),
            reference: Some("latest".to_string()),
            digest: digest.to_string(),
            media_type: "application/vnd.oci.image.manifest.v1+json".to_string(),
            size_bytes: 0,
            bytes: Vec::new(),
            referenced_digests: Vec::new(),
            created_at_unix_ms: 0,
            updated_at_unix_ms: 0,
        }
    }

    #[tokio::test]
    async fn shared_digest_survives_hydration_in_every_repository() {
        let store = FakeResourceStore::default();
        let digest = oci_test_digest(b"shared manifest");

        // The same image content pushed under two names: with digest-only ids
        // the second push overwrote the first and one repository lost its
        // manifest on the next restart.
        for repository in ["nebula/nebula-registry-server", "acme/app"] {
            let manifest = oci_test_manifest(repository, &digest);
            store
                .put_resource(
                    None,
                    "oci_manifest",
                    &oci_manifest_id(repository, &digest),
                    serde_json::to_value(&manifest).unwrap(),
                )
                .await
                .unwrap();
        }

        let mut registry = InMemoryRegistry::default();
        hydrate_registry_from_store(&store, &mut registry)
            .await
            .unwrap();

        for repository in ["nebula/nebula-registry-server", "acme/app"] {
            assert!(
                registry
                    .oci_manifests
                    .contains_key(&(repository.to_string(), digest.clone())),
                "{repository} lost its manifest across hydration"
            );
        }
    }

    #[tokio::test]
    async fn legacy_digest_keyed_manifests_still_hydrate() {
        let store = FakeResourceStore::default();
        let digest = oci_test_digest(b"legacy manifest");
        let repository = "nebula/nebula-registry-server";
        let manifest = oci_test_manifest(repository, &digest);

        // Records written before ids were scoped per repository are stored
        // under the bare digest; they carry the repository in the payload, so
        // they must still land in the right slot without a migration.
        store
            .put_resource(
                None,
                "oci_manifest",
                &digest,
                serde_json::to_value(&manifest).unwrap(),
            )
            .await
            .unwrap();

        let mut registry = InMemoryRegistry::default();
        hydrate_registry_from_store(&store, &mut registry)
            .await
            .unwrap();

        assert!(
            registry
                .oci_manifests
                .contains_key(&(repository.to_string(), digest))
        );
    }

    #[test]
    fn server_generated_auth_token_rejects_admin_scope_and_bad_ttl() {
        let repository_id = RepositoryId::new("repo_a");
        let admin_scope = create_server_auth_token(
            repository_id.clone(),
            CreateAuthTokenRequest {
                name: "admin token".to_string(),
                actor: Actor::User("alice".to_string()),
                kind: AuthTokenKind::User,
                scopes: vec![PolicyAction::ManageAuth],
                org_id: None,
                expires_at_unix_ms: None,
            },
        );
        assert!(admin_scope.is_err());

        let expired = create_server_auth_token(
            repository_id,
            CreateAuthTokenRequest {
                name: "expired token".to_string(),
                actor: Actor::User("alice".to_string()),
                kind: AuthTokenKind::User,
                scopes: vec![PolicyAction::ReadBlob],
                org_id: None,
                expires_at_unix_ms: Some(now_unix_ms().saturating_sub(1)),
            },
        );
        assert!(expired.is_err());
    }

    #[test]
    fn protected_routes_have_explicit_authorization_metadata() {
        let routes = [
            (Method::POST, "/v1/galaxies"),
            (Method::GET, "/v1/galaxies/repo_1"),
            (Method::PUT, "/v1/galaxies/repo_1/merge-intents"),
            (Method::PUT, "/v1/galaxies/repo_1/operations"),
            (Method::PUT, "/v1/galaxies/repo_1/auth-tokens"),
            (Method::PUT, "/v1/galaxies/repo_1/sync-sessions"),
            (Method::POST, "/v1/galaxies/repo_1/build-projections"),
            (Method::POST, "/v1/galaxies/repo_1/deploy-intents"),
            (
                Method::POST,
                "/v1/galaxies/repo_1/deploy-intents/deploy_1/status",
            ),
            (Method::PUT, "/v1/galaxies/repo_1/cedar-policies"),
            (Method::POST, "/v1/galaxies/repo_1/vector-indexes"),
            (Method::POST, "/v1/galaxies/repo_1/vector-search"),
        ];

        for (method, path) in routes {
            assert!(
                route_metadata(&method, path).is_some(),
                "{method} {path} should have route metadata"
            );
        }
    }

    async fn create_fixture_repository(app: &Router, name: &str, org_id: &str) -> RepositoryId {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/galaxies")
                    .header("authorization", "Bearer setup")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "name": name,
                            "org_id": org_id,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let repo: RepositoryRecord = serde_json::from_slice(&body).unwrap();
        repo.id
    }

    async fn put_fixture_read_policy(app: &Router, repository_id: &RepositoryId) {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/v1/galaxies/{repository_id}/policies"))
                    .header("authorization", "Bearer setup")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "id": "pol_read_repo_a",
                            "repository_id": repository_id,
                            "name": "allow tenant read",
                            "priority": 10,
                            "rules": [{
                                "actor": { "User": "alice" },
                                "environment_id": null,
                                "environment_kind": null,
                                "path_glob": "/v1/galaxies/**",
                            "actions": ["ReadBlob"],
                                "decision": "Allow",
                                "reason": "tenant read fixture"
                            }]
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}

pub fn draft_workspace(request: CreateWorkspaceRequest) -> AgentWorkspace {
    AgentWorkspace {
        id: WorkspaceId::generated(),
        repository_id: request.repository_id,
        base_snapshot_id: request.base_snapshot_id,
        owner: request.owner,
        environment_id: request.environment_id,
    }
}

pub fn draft_proposal(request: CreateProposalRequest) -> Proposal {
    Proposal {
        id: nebula_core::ProposalId::generated(),
        repository_id: request.repository_id,
        title: request.title,
        target_ref_id: request.target_ref_id,
        changeset_ids: request.changeset_ids,
        state: ReviewState::Open,
        policy_checks: Vec::new(),
    }
}
