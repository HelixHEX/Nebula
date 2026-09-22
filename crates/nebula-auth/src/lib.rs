use jsonwebtoken::{
    Algorithm, DecodingKey, Validation, decode, decode_header,
    jwk::{AlgorithmParameters, JwkSet},
};
use nebula_core::{Actor, PolicyAction, RepositoryId};
use serde::{Deserialize, Serialize};
use std::{
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("missing bearer token")]
    MissingBearer,
    #[error("invalid authorization header")]
    InvalidHeader,
    #[error("token missing key id")]
    MissingKid,
    #[error("no matching jwks key")]
    MissingJwk,
    #[error("unsupported jwks algorithm")]
    UnsupportedAlgorithm,
    #[error("token verification failed: {0}")]
    Verification(String),
    #[error("jwks fetch failed: {0}")]
    JwksFetch(String),
    #[error("missing required claim: {0}")]
    MissingClaim(&'static str),
    #[error("invalid custom claim: {0}")]
    InvalidClaim(String),
    #[error("oidc discovery failed: {0}")]
    OidcDiscovery(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthMode {
    Disabled,
    Jwks {
        jwks_url: String,
        issuer: String,
        audience: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NebulaClaims {
    pub sub: String,
    pub iss: String,
    pub aud: AudienceClaim,
    pub exp: usize,
    pub nbf: Option<usize>,
    pub iat: Option<usize>,
    pub actor_kind: Option<String>,
    pub actor_id: Option<String>,
    pub org_id: Option<String>,
    pub repository_id: Option<String>,
    #[serde(default)]
    pub scopes: Vec<PolicyAction>,
    #[serde(default)]
    pub scope: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AudienceClaim {
    One(String),
    Many(Vec<String>),
}

#[derive(Clone, Debug)]
pub struct AuthContext {
    pub subject: String,
    pub issuer: String,
    pub audiences: Vec<String>,
    pub actor: Actor,
    pub org_id: Option<String>,
    pub repository_id: Option<RepositoryId>,
    pub scopes: Vec<PolicyAction>,
}

#[derive(Clone, Debug)]
pub struct JwksVerifier {
    jwks_url: String,
    issuer: String,
    audience: String,
    client: reqwest::Client,
    cache: Arc<RwLock<Option<CachedJwks>>>,
    cache_ttl: Duration,
}

#[derive(Clone, Debug)]
struct CachedJwks {
    fetched_at: Instant,
    jwks: JwkSet,
}

#[derive(Clone, Debug, Deserialize)]
struct OidcDiscoveryDocument {
    issuer: String,
    jwks_uri: String,
}

impl JwksVerifier {
    pub fn new(
        jwks_url: impl Into<String>,
        issuer: impl Into<String>,
        audience: impl Into<String>,
    ) -> Self {
        Self {
            jwks_url: jwks_url.into(),
            issuer: issuer.into(),
            audience: audience.into(),
            client: reqwest::Client::new(),
            cache: Arc::new(RwLock::new(None)),
            cache_ttl: Duration::from_secs(60 * 60),
        }
    }

    pub async fn from_oidc_issuer(
        issuer_url: impl Into<String>,
        audience: impl Into<String>,
    ) -> Result<Self, AuthError> {
        let issuer_url = issuer_url.into();
        let discovery_url = format!(
            "{}/.well-known/openid-configuration",
            issuer_url.trim_end_matches('/')
        );
        let discovery = reqwest::Client::new()
            .get(&discovery_url)
            .send()
            .await
            .map_err(|error| AuthError::OidcDiscovery(error.to_string()))?
            .error_for_status()
            .map_err(|error| AuthError::OidcDiscovery(error.to_string()))?
            .json::<OidcDiscoveryDocument>()
            .await
            .map_err(|error| AuthError::OidcDiscovery(error.to_string()))?;
        Ok(Self::new(
            discovery.jwks_uri,
            discovery.issuer,
            audience.into(),
        ))
    }

    pub async fn verify_bearer(&self, authorization: &str) -> Result<AuthContext, AuthError> {
        let token = authorization
            .strip_prefix("Bearer ")
            .map(str::trim)
            .filter(|token| !token.is_empty())
            .ok_or(AuthError::MissingBearer)?;
        self.verify_token(token).await
    }

    pub async fn verify_token(&self, token: &str) -> Result<AuthContext, AuthError> {
        let header =
            decode_header(token).map_err(|error| AuthError::Verification(error.to_string()))?;
        let kid = header.kid.ok_or(AuthError::MissingKid)?;
        let jwks = self.jwks().await?;
        let refreshed;
        let jwk = if let Some(jwk) = jwks.find(&kid) {
            jwk
        } else {
            refreshed = self.refresh_jwks().await?;
            refreshed.find(&kid).ok_or(AuthError::MissingJwk)?
        };
        let mut validation = Validation::new(algorithm_for_jwk(jwk)?);
        validation.validate_exp = true;
        validation.validate_nbf = true;
        validation.validate_aud = true;
        validation.set_required_spec_claims(&["iss", "aud", "exp", "sub"]);
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&[&self.audience]);
        let data = decode::<NebulaClaims>(
            token,
            &DecodingKey::from_jwk(jwk)
                .map_err(|error| AuthError::Verification(error.to_string()))?,
            &validation,
        )
        .map_err(|error| AuthError::Verification(error.to_string()))?;
        data.claims.into_context()
    }

    async fn jwks(&self) -> Result<JwkSet, AuthError> {
        if let Some(cached) = self
            .cache
            .read()
            .map_err(|_| AuthError::JwksFetch("jwks cache poisoned".to_string()))?
            .clone()
            && cached.fetched_at.elapsed() <= self.cache_ttl
        {
            return Ok(cached.jwks);
        }
        self.refresh_jwks().await
    }

    async fn refresh_jwks(&self) -> Result<JwkSet, AuthError> {
        let jwks = self
            .client
            .get(&self.jwks_url)
            .send()
            .await
            .map_err(|error| AuthError::JwksFetch(error.to_string()))?
            .error_for_status()
            .map_err(|error| AuthError::JwksFetch(error.to_string()))?
            .json::<JwkSet>()
            .await
            .map_err(|error| AuthError::JwksFetch(error.to_string()))?;
        *self
            .cache
            .write()
            .map_err(|_| AuthError::JwksFetch("jwks cache poisoned".to_string()))? =
            Some(CachedJwks {
                fetched_at: Instant::now(),
                jwks: jwks.clone(),
            });
        Ok(jwks)
    }
}

impl NebulaClaims {
    fn into_context(self) -> Result<AuthContext, AuthError> {
        let actor_subject = self.actor_id.clone().unwrap_or_else(|| self.sub.clone());
        let actor = match self.actor_kind.as_deref() {
            Some("team") => Actor::Team(actor_subject),
            Some("agent") => Actor::Agent(actor_subject),
            Some("integration") => Actor::Integration(actor_subject),
            Some("public") => Actor::Public,
            Some("user") | None => Actor::User(actor_subject),
            Some(other) => {
                return Err(AuthError::InvalidClaim(format!(
                    "unknown actor_kind `{other}`"
                )));
            }
        };
        let mut scopes = self.scopes;
        if let Some(scope) = self.scope {
            scopes.extend(scope.split_whitespace().filter_map(scope_to_action));
        }
        if self
            .repository_id
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err(AuthError::InvalidClaim(
                "repository_id cannot be empty".to_string(),
            ));
        }
        if self
            .org_id
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err(AuthError::InvalidClaim(
                "org_id cannot be empty".to_string(),
            ));
        }
        Ok(AuthContext {
            subject: self.sub,
            issuer: self.iss,
            audiences: match self.aud {
                AudienceClaim::One(audience) => vec![audience],
                AudienceClaim::Many(audiences) => audiences,
            },
            actor,
            org_id: self.org_id,
            repository_id: self.repository_id.map(RepositoryId::new),
            scopes,
        })
    }
}

fn algorithm_for_jwk(jwk: &jsonwebtoken::jwk::Jwk) -> Result<Algorithm, AuthError> {
    match &jwk.algorithm {
        AlgorithmParameters::EllipticCurve(curve) => match curve.curve {
            jsonwebtoken::jwk::EllipticCurve::P256 => Ok(Algorithm::ES256),
            jsonwebtoken::jwk::EllipticCurve::P384 => Ok(Algorithm::ES384),
            jsonwebtoken::jwk::EllipticCurve::Ed25519 => Ok(Algorithm::EdDSA),
            jsonwebtoken::jwk::EllipticCurve::P521 => Err(AuthError::UnsupportedAlgorithm),
        },
        AlgorithmParameters::RSA(_) => Ok(Algorithm::RS256),
        AlgorithmParameters::OctetKeyPair(_) => Ok(Algorithm::EdDSA),
        _ => Err(AuthError::UnsupportedAlgorithm),
    }
}

fn scope_to_action(scope: &str) -> Option<PolicyAction> {
    match scope {
        "nebula:read_blob" | "read:blob" => Some(PolicyAction::ReadBlob),
        "nebula:write_changeset" | "write:changeset" => Some(PolicyAction::WriteChangeSet),
        "nebula:merge" | "merge:changeset" => Some(PolicyAction::MergeChangeSet),
        "nebula:projection" | "create:projection" => Some(PolicyAction::CreateProjection),
        "nebula:git_export" | "export:git" => Some(PolicyAction::ExportGit),
        "nebula:deploy" | "deploy" => Some(PolicyAction::Deploy),
        "nebula:manage_auth" | "manage:auth" => Some(PolicyAction::ManageAuth),
        "nebula:manage_deploy_config" | "manage:deploy_config" => {
            Some(PolicyAction::ManageDeployConfig)
        }
        "nebula:manage_webhooks" | "manage:webhooks" => Some(PolicyAction::ManageWebhooks),
        "nebula:sync" | "sync:objects" => Some(PolicyAction::SyncObjects),
        "nebula:review" | "review:proposal" => Some(PolicyAction::ReviewProposal),
        "nebula:checks" | "run:status_check" => Some(PolicyAction::RunStatusCheck),
        "nebula:index" | "index:code" => Some(PolicyAction::IndexCode),
        "nebula:manage_variables" | "env:manage" => Some(PolicyAction::ManageVariables),
        "nebula:read_variable_metadata" | "env:metadata" => {
            Some(PolicyAction::ReadVariableMetadata)
        }
        "nebula:read_encrypted_variable" | "env:read_encrypted" => {
            Some(PolicyAction::ReadEncryptedVariable)
        }
        "nebula:read_variable_value" | "env:read_value" => Some(PolicyAction::ReadVariableValue),
        "nebula:inject_variable" | "env:inject" => Some(PolicyAction::InjectVariable),
        "nebula:reveal_variable" | "env:reveal" => Some(PolicyAction::RevealVariable),
        "nebula:save_secret" | "env:save_secret" => Some(PolicyAction::SaveSecret),
        "nebula:push_secret" | "env:push_secret" => Some(PolicyAction::PushSecret),
        "nebula:export_secret" | "env:export_secret" => Some(PolicyAction::ExportSecret),
        "nebula:use_workspace_for_deploy" | "deploy:workspace" => {
            Some(PolicyAction::UseWorkspaceForDeploy)
        }
        "nebula:mutate_deploy_variables" | "deploy:mutate_env" => {
            Some(PolicyAction::MutateDeployVariables)
        }
        "nebula:manage_variable_policy" | "env:manage_policy" => {
            Some(PolicyAction::ManageVariablePolicy)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oauth_scope_string_maps_to_nebula_actions() {
        let claims = NebulaClaims {
            sub: "user_1".to_string(),
            iss: "https://auth.example.com".to_string(),
            aud: AudienceClaim::One("nebula".to_string()),
            exp: 9_999_999_999,
            nbf: None,
            iat: None,
            actor_kind: Some("user".to_string()),
            actor_id: None,
            org_id: Some("org_1".to_string()),
            repository_id: Some("repo_1".to_string()),
            scopes: Vec::new(),
            scope: Some("read:blob sync:objects manage:webhooks".to_string()),
        };
        let context = claims.into_context().unwrap();
        assert!(context.scopes.contains(&PolicyAction::ReadBlob));
        assert!(context.scopes.contains(&PolicyAction::SyncObjects));
        assert!(context.scopes.contains(&PolicyAction::ManageWebhooks));
        assert_eq!(context.repository_id, Some(RepositoryId::new("repo_1")));
    }
}
