use anyhow::{Context, Result};
use nebula_core::PolicyAction;
use nebula_registry::{AuthTokenAuthority, RegistryBootstrapAuthToken, RegistryConfig};
use std::{env, net::SocketAddr, path::PathBuf, time::Duration};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RegistryBackendMode {
    File,
    Postgres,
    PostgresObjectStore,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QuotaBackendMode {
    Memory,
    External,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthProviderMode {
    BetterAuthRs,
    Jwks,
    Disabled,
}

#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub request_timeout: Duration,
    pub request_body_limit_bytes: usize,
    pub rate_limit_requests_per_second: u64,
    pub quota_backend_mode: QuotaBackendMode,
    pub backend_mode: RegistryBackendMode,
    pub run_migrations: bool,
    pub dev_mode: bool,
    pub auth_provider: AuthProviderMode,
    pub auth_required: bool,
    pub auth_issuer: Option<String>,
    pub auth_audience: Option<String>,
    pub auth_base_url: Option<String>,
    pub auth_secret: Option<String>,
    pub admin_api_enabled: bool,
    pub admin_require_better_auth: bool,
    pub admin_bootstrap_emails: Vec<String>,
    pub admin_bootstrap_user_ids: Vec<String>,
    pub admin_bootstrap_role: String,
    pub admin_webhook_secret: Option<String>,
    pub registry: RegistryConfig,
}

impl ServerConfig {
    pub fn from_env() -> Result<Self> {
        let backend_mode = match env::var("NEBULA_REGISTRY_BACKEND")
            .unwrap_or_else(|_| "file".to_string())
            .trim()
        {
            "file" => RegistryBackendMode::File,
            "postgres" => RegistryBackendMode::Postgres,
            "postgres-object-store" => RegistryBackendMode::PostgresObjectStore,
            other => anyhow::bail!(
                "NEBULA_REGISTRY_BACKEND must be file, postgres, or postgres-object-store, got {other}"
            ),
        };
        let dev_mode = env_flag("NEBULA_REGISTRY_DEV_MODE", false);
        let host = env::var("HOST").unwrap_or_else(|_| {
            if dev_mode {
                "127.0.0.1".to_string()
            } else {
                "0.0.0.0".to_string()
            }
        });
        let port = env::var("PORT")
            .unwrap_or_else(|_| "8080".to_string())
            .parse::<u16>()
            .context("PORT must be a valid u16")?;
        let request_timeout = Duration::from_secs(
            env::var("NEBULA_REQUEST_TIMEOUT_SECONDS")
                .unwrap_or_else(|_| "30".to_string())
                .parse::<u64>()
                .context("NEBULA_REQUEST_TIMEOUT_SECONDS must be a valid u64")?,
        );
        let request_body_limit_bytes = env::var("NEBULA_REQUEST_BODY_LIMIT_BYTES")
            .unwrap_or_else(|_| (16 * 1024 * 1024).to_string())
            .parse::<usize>()
            .context("NEBULA_REQUEST_BODY_LIMIT_BYTES must be a valid usize")?;
        let rate_limit_requests_per_second = env::var("NEBULA_RATE_LIMIT_REQUESTS_PER_SECOND")
            .unwrap_or_else(|_| "512".to_string())
            .parse::<u64>()
            .context("NEBULA_RATE_LIMIT_REQUESTS_PER_SECOND must be a valid u64")?;
        let quota_backend_mode = match env::var("NEBULA_QUOTA_BACKEND")
            .unwrap_or_else(|_| "memory".to_string())
            .as_str()
        {
            "memory" => QuotaBackendMode::Memory,
            "external" => QuotaBackendMode::External,
            other => anyhow::bail!("NEBULA_QUOTA_BACKEND must be memory or external, got {other}"),
        };
        let run_migrations = env_flag("NEBULA_RUN_MIGRATIONS", true);
        let auth_required = env_flag("NEBULA_AUTH_REQUIRED", !dev_mode);
        let auth_issuer = env::var("NEBULA_AUTH_ISSUER").ok();
        let auth_audience = env::var("NEBULA_AUTH_AUDIENCE").ok();
        let auth_jwks_url = env::var("NEBULA_AUTH_JWKS_URL").ok();
        let auth_provider = match env::var("NEBULA_AUTH_PROVIDER")
            .unwrap_or_else(|_| {
                if auth_required {
                    "jwks".to_string()
                } else {
                    "disabled".to_string()
                }
            })
            .as_str()
        {
            "better-auth-rs" => AuthProviderMode::BetterAuthRs,
            "jwks" => AuthProviderMode::Jwks,
            "disabled" => AuthProviderMode::Disabled,
            other => anyhow::bail!(
                "NEBULA_AUTH_PROVIDER must be better-auth-rs, jwks, or disabled, got {other}"
            ),
        };
        let auth_base_url = env::var("NEBULA_AUTH_BASE_URL").ok();
        let auth_secret = env::var("NEBULA_AUTH_SECRET").ok();
        let auth_token_authority = match env::var("NEBULA_AUTH_TOKEN_AUTHORITY")
            .unwrap_or_else(|_| {
                if matches!(auth_provider, AuthProviderMode::BetterAuthRs)
                    || auth_jwks_url.is_some()
                {
                    "astracollab-hosted".to_string()
                } else {
                    "nebula-self-hosted".to_string()
                }
            })
            .as_str()
        {
            "astracollab-hosted" => AuthTokenAuthority::AstracollabHosted,
            "nebula-self-hosted" => AuthTokenAuthority::NebulaSelfHosted,
            other => anyhow::bail!(
                "NEBULA_AUTH_TOKEN_AUTHORITY must be astracollab-hosted or nebula-self-hosted, got {other}"
            ),
        };
        let postgres_url = env::var("DATABASE_URL").ok();
        let blob_store_url = env::var("BLOB_STORE_URL").ok();
        let vector_store_url = env::var("VECTOR_STORE_URL").ok();
        let astracollab_deploy_url = env::var("ASTRACOLLAB_DEPLOY_URL").ok();
        let astracollab_deploy_signing_secret = env::var("ASTRACOLLAB_DEPLOY_SIGNING_SECRET").ok();
        let registry_public_url = env::var("NEBULA_REGISTRY_PUBLIC_URL")
            .ok()
            .or_else(|| auth_base_url.clone());
        let telemetry_sinks = env::var("NEBULA_TELEMETRY_SINKS")
            .unwrap_or_else(|_| "json,prometheus".to_string())
            .split(',')
            .map(str::trim)
            .filter(|sink| !sink.is_empty())
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        let telemetry_event_file = env::var("NEBULA_TELEMETRY_EVENT_FILE")
            .ok()
            .map(PathBuf::from);
        let telemetry_webhook_url = env::var("NEBULA_TELEMETRY_WEBHOOK_URL").ok();
        let telemetry_webhook_secret = env::var("NEBULA_TELEMETRY_WEBHOOK_SECRET").ok();
        let admin_api_enabled = env_flag("NEBULA_ADMIN_API_ENABLED", auth_required);
        let admin_require_better_auth = env_flag("NEBULA_ADMIN_REQUIRE_BETTER_AUTH", true);
        let admin_bootstrap_emails = env_list("NEBULA_ADMIN_BOOTSTRAP_EMAILS");
        let admin_bootstrap_user_ids = env_list("NEBULA_ADMIN_BOOTSTRAP_USER_IDS");
        let admin_bootstrap_role =
            env::var("NEBULA_ADMIN_BOOTSTRAP_ROLE").unwrap_or_else(|_| "owner".to_string());
        let admin_webhook_secret = env::var("NEBULA_ADMIN_WEBHOOK_SECRET").ok();

        if !matches!(backend_mode, RegistryBackendMode::File) && postgres_url.is_none() {
            anyhow::bail!("DATABASE_URL is required for production registry backend");
        }
        if matches!(backend_mode, RegistryBackendMode::PostgresObjectStore)
            && blob_store_url.is_none()
        {
            anyhow::bail!("BLOB_STORE_URL is required for postgres-object-store backend");
        }
        if !auth_required && !dev_mode {
            anyhow::bail!(
                "disabling registry auth requires NEBULA_REGISTRY_DEV_MODE=1 for explicit local development"
            );
        }
        // AuthProviderMode::Disabled means no external/JWKS provider. It can still
        // run authenticated with Nebula self-hosted stored tokens.
        if !auth_required && host != "127.0.0.1" && host != "localhost" {
            anyhow::bail!("unauthenticated registry dev mode must bind to 127.0.0.1 or localhost");
        }
        if matches!(auth_provider, AuthProviderMode::BetterAuthRs) {
            if auth_secret.as_ref().is_none_or(|secret| secret.len() < 32) {
                anyhow::bail!("NEBULA_AUTH_SECRET must be at least 32 bytes for Better Auth RS");
            }
            if auth_base_url.is_none() {
                anyhow::bail!("NEBULA_AUTH_BASE_URL is required for Better Auth RS");
            }
            if !dev_mode && postgres_url.is_none() {
                anyhow::bail!("DATABASE_URL is required for Better Auth RS outside local dev mode");
            }
        }
        if admin_api_enabled
            && admin_require_better_auth
            && !matches!(auth_provider, AuthProviderMode::BetterAuthRs)
        {
            anyhow::bail!(
                "NEBULA_ADMIN_REQUIRE_BETTER_AUTH=true requires NEBULA_AUTH_PROVIDER=better-auth-rs"
            );
        }
        if admin_bootstrap_role != "owner" && admin_bootstrap_role != "operator" {
            anyhow::bail!("NEBULA_ADMIN_BOOTSTRAP_ROLE must be owner or operator");
        }
        if auth_required
            && matches!(auth_provider, AuthProviderMode::Jwks)
            && (auth_issuer.is_none() || auth_audience.is_none() || auth_jwks_url.is_none())
        {
            anyhow::bail!(
                "NEBULA_AUTH_ISSUER, NEBULA_AUTH_AUDIENCE, and NEBULA_AUTH_JWKS_URL are required when NEBULA_AUTH_PROVIDER=jwks"
            );
        }

        Ok(Self {
            host,
            port,
            request_timeout,
            request_body_limit_bytes,
            rate_limit_requests_per_second,
            quota_backend_mode,
            backend_mode,
            run_migrations,
            dev_mode,
            auth_provider,
            auth_required,
            auth_issuer: auth_issuer.clone(),
            auth_audience: auth_audience.clone(),
            auth_base_url,
            auth_secret,
            admin_api_enabled,
            admin_require_better_auth,
            admin_bootstrap_emails,
            admin_bootstrap_user_ids,
            admin_bootstrap_role,
            admin_webhook_secret,
            registry: RegistryConfig {
                service_name: env::var("NEBULA_SERVICE_NAME")
                    .unwrap_or_else(|_| "nebula-registry".to_string()),
                postgres_url,
                blob_store_url,
                vector_store_url,
                auth_required,
                auth_issuer,
                auth_audience,
                auth_jwks_url,
                auth_token_authority,
                public_base_url: registry_public_url,
                astracollab_deploy_url,
                astracollab_deploy_signing_secret,
                telemetry_sinks,
                telemetry_event_file,
                telemetry_webhook_url,
                telemetry_webhook_secret,
                bootstrap_auth_tokens: bootstrap_auth_tokens_from_env(),
                persistence_path: env::var("NEBULA_REGISTRY_PERSISTENCE_PATH")
                    .ok()
                    .map(PathBuf::from),
            },
        })
    }

    pub fn addr(&self) -> Result<SocketAddr> {
        format!("{}:{}", self.host, self.port)
            .parse()
            .context("HOST/PORT must form a valid socket address")
    }
}

fn env_flag(name: &str, default: bool) -> bool {
    match env::var(name) {
        Ok(value) => matches!(
            value.trim().to_lowercase().as_str(),
            "1" | "true" | "on" | "yes"
        ),
        Err(_) => default,
    }
}

fn env_list(name: &str) -> Vec<String> {
    env::var(name)
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .collect()
}

fn bootstrap_auth_tokens_from_env() -> Vec<RegistryBootstrapAuthToken> {
    let mut tokens = Vec::new();
    if let Ok(raw_token) = env::var("NEBULA_REGISTRY_BUILDER_TOKEN") {
        if !raw_token.trim().is_empty() {
            tokens.push(RegistryBootstrapAuthToken {
                name: "horizon-builder".to_string(),
                raw_token,
                scopes: vec![PolicyAction::PushImage, PolicyAction::PullImage],
            });
        }
    }
    if let Ok(raw_token) = env::var("NEBULA_REGISTRY_READER_TOKEN") {
        if !raw_token.trim().is_empty() {
            tokens.push(RegistryBootstrapAuthToken {
                name: "horizon-reader".to_string(),
                raw_token,
                scopes: vec![PolicyAction::PullImage],
            });
        }
    }
    tokens
}
