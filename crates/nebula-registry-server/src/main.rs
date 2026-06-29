mod admin;
mod better_auth_bridge;
mod better_auth_migrations;
mod config;
mod health;
mod shutdown;
mod telemetry;

use anyhow::Result;
use axum::{
    Router,
    body::Body,
    extract::{DefaultBodyLimit, State},
    http::{HeaderName, StatusCode, header},
    middleware::{Next, from_fn_with_state},
    response::{IntoResponse, Response},
    routing::get,
};
use config::{AuthProviderMode, ServerConfig};
use nebula_storage::PostgresMetadataStore;
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::net::TcpListener;
use tower_http::{
    limit::RequestBodyLimitLayer,
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    timeout::TimeoutLayer,
    trace::TraceLayer,
};

#[tokio::main]
async fn main() -> Result<()> {
    telemetry::init();
    let config = ServerConfig::from_env()?;
    run_startup_migrations(&config).await?;
    let addr = config.addr()?;
    let app = app(config.clone()).await?;
    let listener = TcpListener::bind(addr).await?;

    tracing::info!(
        %addr,
        backend_mode = ?config.backend_mode,
        quota_backend = ?config.quota_backend_mode,
        auth_provider = ?config.auth_provider,
        auth_required = config.auth_required,
        auth_issuer = ?config.auth_issuer,
        auth_audience = ?config.auth_audience,
        "starting Nebula Registry server"
    );
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown::signal())
        .await?;
    tracing::info!("Nebula Registry server stopped");
    Ok(())
}

async fn app(config: ServerConfig) -> Result<Router> {
    let request_id_header = HeaderName::from_static("x-request-id");
    let rate_limit = RateLimitState::new(config.rate_limit_requests_per_second);
    let metrics = MetricsState::default();
    let readiness = health::ReadinessState {
        postgres_url: config.registry.postgres_url.clone(),
        blob_store_url: config.registry.blob_store_url.clone(),
        vector_store_url: config.registry.vector_store_url.clone(),
    };
    let better_auth = if matches!(config.auth_provider, AuthProviderMode::BetterAuthRs) {
        Some(better_auth_bridge::build(&config).await?)
    } else {
        None
    };
    let external_auth_provider = better_auth.as_ref().map(|auth| auth.verifier.clone());
    let admin_state = if config.admin_api_enabled {
        Some(
            admin::build_state(
                &config,
                better_auth.clone(),
                readiness.clone(),
                metrics.clone(),
            )
            .await?,
        )
    } else {
        None
    };
    let mut app = nebula_registry::router_async_with_auth_provider(
        config.registry.clone(),
        external_auth_provider,
    )
    .await
    .map_err(anyhow::Error::msg)?;
    if let Some(auth) = better_auth {
        app = app.nest("/auth", auth.router);
    }
    if let Some(admin_state) = admin_state {
        app = app.nest("/admin/v1", admin::router(admin_state));
    }
    Ok(app
        .route(
            "/metrics",
            get({
                let metrics = metrics.clone();
                move || {
                    let metrics = metrics.clone();
                    async move { health::metrics(metrics.snapshot()).await }
                }
            }),
        )
        .layer(TraceLayer::new_for_http())
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            config.request_timeout,
        ))
        .layer(DefaultBodyLimit::max(config.request_body_limit_bytes))
        .layer(RequestBodyLimitLayer::new(config.request_body_limit_bytes))
        .layer(from_fn_with_state(rate_limit, rate_limit_middleware))
        .layer(from_fn_with_state(metrics, metrics_middleware))
        .layer(PropagateRequestIdLayer::new(request_id_header.clone()))
        .layer(SetRequestIdLayer::new(request_id_header, MakeRequestUuid)))
}

async fn run_startup_migrations(config: &ServerConfig) -> Result<()> {
    if !config.run_migrations {
        return Ok(());
    }
    let Some(database_url) = &config.registry.postgres_url else {
        return Ok(());
    };
    let store = PostgresMetadataStore::connect(database_url).await?;
    store.run_migrations().await?;
    if matches!(config.auth_provider, AuthProviderMode::BetterAuthRs) {
        better_auth_migrations::run(database_url).await?;
    }
    Ok(())
}

#[derive(Clone)]
struct RateLimitState {
    requests_per_second: u64,
    buckets: Arc<Mutex<BTreeMap<String, RateLimitBucket>>>,
}

struct RateLimitBucket {
    window_started_at: Instant,
    request_count: u64,
}

impl RateLimitState {
    fn new(requests_per_second: u64) -> Self {
        Self {
            requests_per_second,
            buckets: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

#[derive(Clone, Default)]
pub(crate) struct MetricsState {
    requests_total: Arc<AtomicU64>,
    responses_total: Arc<AtomicU64>,
    rate_limited_total: Arc<AtomicU64>,
    server_errors_total: Arc<AtomicU64>,
    auth_failures_total: Arc<AtomicU64>,
    cas_conflicts_total: Arc<AtomicU64>,
    vector_requests_total: Arc<AtomicU64>,
    deploy_handoffs_total: Arc<AtomicU64>,
    deploy_callbacks_total: Arc<AtomicU64>,
    latency_micros_total: Arc<AtomicU64>,
}

impl MetricsState {
    pub(crate) fn snapshot(&self) -> health::MetricsSnapshot {
        health::MetricsSnapshot {
            requests_total: self.requests_total.load(Ordering::Relaxed),
            responses_total: self.responses_total.load(Ordering::Relaxed),
            rate_limited_total: self.rate_limited_total.load(Ordering::Relaxed),
            server_errors_total: self.server_errors_total.load(Ordering::Relaxed),
            auth_failures_total: self.auth_failures_total.load(Ordering::Relaxed),
            cas_conflicts_total: self.cas_conflicts_total.load(Ordering::Relaxed),
            vector_requests_total: self.vector_requests_total.load(Ordering::Relaxed),
            deploy_handoffs_total: self.deploy_handoffs_total.load(Ordering::Relaxed),
            deploy_callbacks_total: self.deploy_callbacks_total.load(Ordering::Relaxed),
            latency_micros_total: self.latency_micros_total.load(Ordering::Relaxed),
        }
    }
}

async fn metrics_middleware(
    State(state): State<MetricsState>,
    request: axum::http::Request<Body>,
    next: Next,
) -> Response {
    let path = request.uri().path().to_string();
    let started_at = Instant::now();
    state.requests_total.fetch_add(1, Ordering::Relaxed);
    if path.contains("/vector-") {
        state.vector_requests_total.fetch_add(1, Ordering::Relaxed);
    }
    if path.ends_with("/deploy-intents") {
        state.deploy_handoffs_total.fetch_add(1, Ordering::Relaxed);
    }
    if path.contains("/deploy-intents/") && path.ends_with("/status") {
        state.deploy_callbacks_total.fetch_add(1, Ordering::Relaxed);
    }
    let response = next.run(request).await;
    state.latency_micros_total.fetch_add(
        started_at.elapsed().as_micros().min(u128::from(u64::MAX)) as u64,
        Ordering::Relaxed,
    );
    state.responses_total.fetch_add(1, Ordering::Relaxed);
    if response.status().is_server_error() {
        state.server_errors_total.fetch_add(1, Ordering::Relaxed);
    }
    if response.status() == StatusCode::TOO_MANY_REQUESTS {
        state.rate_limited_total.fetch_add(1, Ordering::Relaxed);
    }
    if response.status() == StatusCode::UNAUTHORIZED || response.status() == StatusCode::FORBIDDEN {
        state.auth_failures_total.fetch_add(1, Ordering::Relaxed);
    }
    if response.status() == StatusCode::CONFLICT {
        state.cas_conflicts_total.fetch_add(1, Ordering::Relaxed);
    }
    response
}

async fn rate_limit_middleware(
    State(state): State<RateLimitState>,
    request: axum::http::Request<Body>,
    next: Next,
) -> Response {
    if state.requests_per_second == 0 {
        return next.run(request).await;
    }
    {
        let key = rate_limit_key(&request);
        let mut buckets = state.buckets.lock().expect("rate limit bucket poisoned");
        let bucket = buckets.entry(key).or_insert_with(|| RateLimitBucket {
            window_started_at: Instant::now(),
            request_count: 0,
        });
        if bucket.window_started_at.elapsed() >= Duration::from_secs(1) {
            bucket.window_started_at = Instant::now();
            bucket.request_count = 0;
        }
        if bucket.request_count >= state.requests_per_second {
            let mut response = (
                StatusCode::TOO_MANY_REQUESTS,
                "registry rate limit exceeded",
            )
                .into_response();
            response.headers_mut().insert(
                header::RETRY_AFTER,
                axum::http::HeaderValue::from_static("1"),
            );
            return response;
        }
        bucket.request_count += 1;
    }
    next.run(request).await
}

fn rate_limit_key(request: &axum::http::Request<Body>) -> String {
    request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(|value| format!("auth:{}", stable_header_fingerprint(value)))
        .or_else(|| {
            request
                .headers()
                .get("x-forwarded-for")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.split(',').next())
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|value| format!("ip:{value}"))
        })
        .unwrap_or_else(|| "anonymous".to_string())
}

fn stable_header_fingerprint(value: &str) -> u64 {
    value
        .bytes()
        .fold(14_695_981_039_346_656_037_u64, |hash, byte| {
            (hash ^ u64::from(byte)).wrapping_mul(1_099_511_628_211)
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use config::{AuthProviderMode, QuotaBackendMode, RegistryBackendMode};
    use nebula_registry::{AuthTokenAuthority, RegistryConfig};
    use tower::ServiceExt;

    #[tokio::test]
    async fn better_auth_routes_mount_in_dev_memory_mode() {
        let config = ServerConfig {
            host: "127.0.0.1".to_string(),
            port: 8080,
            request_timeout: Duration::from_secs(30),
            request_body_limit_bytes: 1024 * 1024,
            rate_limit_requests_per_second: 512,
            quota_backend_mode: QuotaBackendMode::Memory,
            backend_mode: RegistryBackendMode::File,
            run_migrations: false,
            dev_mode: true,
            auth_provider: AuthProviderMode::BetterAuthRs,
            auth_required: false,
            auth_issuer: None,
            auth_audience: None,
            auth_base_url: Some("http://127.0.0.1:8080".to_string()),
            auth_secret: Some("test-secret-key-at-least-32-bytes".to_string()),
            admin_api_enabled: false,
            admin_require_better_auth: true,
            admin_bootstrap_emails: Vec::new(),
            admin_bootstrap_user_ids: Vec::new(),
            admin_bootstrap_role: "owner".to_string(),
            admin_webhook_secret: None,
            registry: RegistryConfig {
                service_name: "nebula-registry-test".to_string(),
                postgres_url: None,
                blob_store_url: None,
                vector_store_url: None,
                auth_required: false,
                auth_issuer: None,
                auth_audience: None,
                auth_jwks_url: None,
                auth_token_authority: AuthTokenAuthority::AstracollabHosted,
                public_base_url: Some("http://127.0.0.1:8080".to_string()),
                astracollab_deploy_url: None,
                astracollab_deploy_signing_secret: None,
                telemetry_sinks: Vec::new(),
                telemetry_event_file: None,
                telemetry_webhook_url: None,
                telemetry_webhook_secret: None,
                persistence_path: None,
            },
        };

        let app = app(config).await.expect("app should build");
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/auth/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }
}
