use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post, put},
};
use nebula_core::{
    NebulaTelemetryContext, NebulaTelemetryEvent, TelemetrySeverity, TelemetrySource,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use crate::{
    better_auth_bridge::{AdminIdentity, BetterAuthRegistry},
    config::{AuthProviderMode, ServerConfig},
    health::{self, ReadinessState},
};

#[derive(Clone)]
pub struct AdminState {
    auth: Option<BetterAuthRegistry>,
    auth_provider: AuthProviderMode,
    require_better_auth: bool,
    store: AdminStore,
    readiness: ReadinessState,
    metrics: crate::MetricsState,
    telemetry_event_file: Option<PathBuf>,
    webhook_secret: Option<String>,
    http_client: reqwest::Client,
}

#[derive(Clone)]
enum AdminStore {
    Memory(Arc<Mutex<MemoryAdminStore>>),
    Postgres(PgPool),
}

#[derive(Default)]
struct MemoryAdminStore {
    admins: BTreeMap<String, PlatformAdminRecord>,
    webhooks: BTreeMap<String, TelemetryWebhookRecord>,
    telemetry_events: Vec<NebulaTelemetryEvent>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PlatformAdminRecord {
    pub id: String,
    pub user_id: Option<String>,
    pub email: Option<String>,
    pub role: String,
    pub status: String,
    pub created_at_unix_ms: u64,
    pub updated_at_unix_ms: u64,
    pub created_by: Option<String>,
    pub notes: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TelemetryWebhookRecord {
    pub id: String,
    pub url: String,
    pub status: String,
    pub secret: Option<String>,
    pub created_at_unix_ms: u64,
    pub updated_at_unix_ms: u64,
    pub last_delivery_status: Option<String>,
    pub last_delivery_at_unix_ms: Option<u64>,
    pub last_error: Option<String>,
}

#[derive(Debug)]
struct AdminError {
    status: StatusCode,
    message: String,
}

impl AdminError {
    fn unauthorized(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: message.into(),
        }
    }

    fn forbidden(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            message: message.into(),
        }
    }

    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: message.into(),
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: message.into(),
        }
    }
}

impl IntoResponse for AdminError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({ "error": self.message }))).into_response()
    }
}

pub async fn build_state(
    config: &ServerConfig,
    auth: Option<BetterAuthRegistry>,
    readiness: ReadinessState,
    metrics: crate::MetricsState,
) -> Result<AdminState, anyhow::Error> {
    let store = if let Some(database_url) = &config.registry.postgres_url {
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(database_url)
            .await?;
        run_admin_migrations(&pool).await?;
        AdminStore::Postgres(pool)
    } else {
        AdminStore::Memory(Arc::new(Mutex::new(MemoryAdminStore::default())))
    };

    let state = AdminState {
        auth,
        auth_provider: config.auth_provider.clone(),
        require_better_auth: config.admin_require_better_auth,
        store,
        readiness,
        metrics,
        telemetry_event_file: config.registry.telemetry_event_file.clone(),
        webhook_secret: config.admin_webhook_secret.clone(),
        http_client: reqwest::Client::new(),
    };

    state
        .bootstrap_platform_admins(
            &config.admin_bootstrap_user_ids,
            &config.admin_bootstrap_emails,
            &config.admin_bootstrap_role,
        )
        .await?;

    Ok(state)
}

pub fn router(state: AdminState) -> Router {
    Router::new()
        .route("/health/live", get(admin_health_live))
        .route("/health/ready", get(admin_health_ready))
        .route("/metrics", get(admin_metrics))
        .route(
            "/telemetry/events",
            get(list_telemetry_events).post(ingest_telemetry_event),
        )
        .route("/telemetry/summary", get(telemetry_summary))
        .route("/webhooks/telemetry", get(list_telemetry_webhooks))
        .route("/webhooks/telemetry/{id}", put(upsert_telemetry_webhook))
        .route(
            "/webhooks/telemetry/{id}/test",
            post(test_telemetry_webhook),
        )
        .route("/platform-admins", get(list_platform_admins))
        .route(
            "/platform-admins/{principal}",
            put(upsert_platform_admin).delete(delete_platform_admin),
        )
        .with_state(state)
}

async fn run_admin_migrations(pool: &PgPool) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS nebula_platform_admins (
            id TEXT PRIMARY KEY,
            user_id TEXT UNIQUE,
            email TEXT UNIQUE,
            role TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at_unix_ms BIGINT NOT NULL,
            updated_at_unix_ms BIGINT NOT NULL,
            created_by TEXT,
            notes TEXT
        )
        "#,
    )
    .execute(pool)
    .await?;
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS nebula_admin_telemetry_webhooks (
            id TEXT PRIMARY KEY,
            url TEXT NOT NULL,
            status TEXT NOT NULL,
            secret TEXT,
            created_at_unix_ms BIGINT NOT NULL,
            updated_at_unix_ms BIGINT NOT NULL,
            last_delivery_status TEXT,
            last_delivery_at_unix_ms BIGINT,
            last_error TEXT
        )
        "#,
    )
    .execute(pool)
    .await?;
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS nebula_admin_telemetry_events (
            event_id TEXT PRIMARY KEY,
            event_json JSONB NOT NULL,
            created_at_unix_ms BIGINT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;
    Ok(())
}

impl AdminState {
    async fn require_admin(&self, headers: &HeaderMap) -> Result<AdminIdentity, AdminError> {
        if self.require_better_auth && !matches!(self.auth_provider, AuthProviderMode::BetterAuthRs)
        {
            return Err(AdminError::forbidden(
                "admin api requires NEBULA_AUTH_PROVIDER=better-auth-rs",
            ));
        }
        let token = bearer_token(headers)
            .ok_or_else(|| AdminError::unauthorized("missing bearer token"))?;
        let auth = self
            .auth
            .as_ref()
            .ok_or_else(|| AdminError::forbidden("Better Auth RS is not configured"))?;
        let identity = auth
            .verify_admin_bearer(&token)
            .await
            .map_err(AdminError::unauthorized)?;
        if !self.is_platform_admin(&identity).await? {
            return Err(AdminError::forbidden("platform admin access is required"));
        }
        Ok(identity)
    }

    async fn bootstrap_platform_admins(
        &self,
        user_ids: &[String],
        emails: &[String],
        role: &str,
    ) -> Result<(), anyhow::Error> {
        for user_id in user_ids {
            self.upsert_platform_admin_record(PlatformAdminRecord {
                id: format!("user:{user_id}"),
                user_id: Some(user_id.clone()),
                email: None,
                role: role.to_string(),
                status: "active".to_string(),
                created_at_unix_ms: unix_ms(),
                updated_at_unix_ms: unix_ms(),
                created_by: Some("bootstrap".to_string()),
                notes: Some("Created from NEBULA_ADMIN_BOOTSTRAP_USER_IDS".to_string()),
            })
            .await
            .map_err(|error| anyhow::anyhow!(error.message))?;
        }
        for email in emails {
            self.upsert_platform_admin_record(PlatformAdminRecord {
                id: format!("email:{}", email.to_lowercase()),
                user_id: None,
                email: Some(email.to_lowercase()),
                role: role.to_string(),
                status: "active".to_string(),
                created_at_unix_ms: unix_ms(),
                updated_at_unix_ms: unix_ms(),
                created_by: Some("bootstrap".to_string()),
                notes: Some("Created from NEBULA_ADMIN_BOOTSTRAP_EMAILS".to_string()),
            })
            .await
            .map_err(|error| anyhow::anyhow!(error.message))?;
        }
        Ok(())
    }

    async fn is_platform_admin(&self, identity: &AdminIdentity) -> Result<bool, AdminError> {
        match &self.store {
            AdminStore::Memory(store) => {
                let store = store
                    .lock()
                    .map_err(|_| AdminError::internal("admin store lock poisoned"))?;
                Ok(store.admins.values().any(|admin| {
                    admin.status == "active"
                        && (admin.user_id.as_deref() == Some(identity.user_id.as_str())
                            || identity.email.as_ref().is_some_and(|email| {
                                admin.email.as_deref() == Some(email.as_str())
                            }))
                }))
            }
            AdminStore::Postgres(pool) => {
                let count = sqlx::query_scalar::<_, i64>(
                    r#"
                    SELECT COUNT(*)
                    FROM nebula_platform_admins
                    WHERE status = 'active'
                      AND (user_id = $1 OR ($2::text IS NOT NULL AND email = $2))
                    "#,
                )
                .bind(&identity.user_id)
                .bind(identity.email.as_deref())
                .fetch_one(pool)
                .await
                .map_err(|error| AdminError::internal(error.to_string()))?;
                Ok(count > 0)
            }
        }
    }

    async fn list_admins(&self) -> Result<Vec<PlatformAdminRecord>, AdminError> {
        match &self.store {
            AdminStore::Memory(store) => {
                let store = store
                    .lock()
                    .map_err(|_| AdminError::internal("admin store lock poisoned"))?;
                Ok(store.admins.values().cloned().collect())
            }
            AdminStore::Postgres(pool) => sqlx::query_as::<_, PlatformAdminRow>(
                r#"
                SELECT id, user_id, email, role, status, created_at_unix_ms,
                       updated_at_unix_ms, created_by, notes
                FROM nebula_platform_admins
                ORDER BY created_at_unix_ms DESC
                "#,
            )
            .fetch_all(pool)
            .await
            .map(|rows| rows.into_iter().map(Into::into).collect())
            .map_err(|error| AdminError::internal(error.to_string())),
        }
    }

    async fn upsert_platform_admin_record(
        &self,
        mut record: PlatformAdminRecord,
    ) -> Result<PlatformAdminRecord, AdminError> {
        if record.role != "owner" && record.role != "operator" {
            return Err(AdminError::bad_request("role must be owner or operator"));
        }
        if record.status != "active" && record.status != "disabled" {
            return Err(AdminError::bad_request("status must be active or disabled"));
        }
        record.updated_at_unix_ms = unix_ms();
        match &self.store {
            AdminStore::Memory(store) => {
                let mut store = store
                    .lock()
                    .map_err(|_| AdminError::internal("admin store lock poisoned"))?;
                store.admins.insert(record.id.clone(), record.clone());
                Ok(record)
            }
            AdminStore::Postgres(pool) => {
                sqlx::query(
                    r#"
                    INSERT INTO nebula_platform_admins (
                        id, user_id, email, role, status, created_at_unix_ms,
                        updated_at_unix_ms, created_by, notes
                    )
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                    ON CONFLICT (id) DO UPDATE SET
                        user_id = EXCLUDED.user_id,
                        email = EXCLUDED.email,
                        role = EXCLUDED.role,
                        status = EXCLUDED.status,
                        updated_at_unix_ms = EXCLUDED.updated_at_unix_ms,
                        created_by = COALESCE(nebula_platform_admins.created_by, EXCLUDED.created_by),
                        notes = EXCLUDED.notes
                    "#,
                )
                .bind(&record.id)
                .bind(&record.user_id)
                .bind(&record.email)
                .bind(&record.role)
                .bind(&record.status)
                .bind(record.created_at_unix_ms as i64)
                .bind(record.updated_at_unix_ms as i64)
                .bind(&record.created_by)
                .bind(&record.notes)
                .execute(pool)
                .await
                .map_err(|error| AdminError::internal(error.to_string()))?;
                Ok(record)
            }
        }
    }

    async fn delete_platform_admin_record(&self, principal: &str) -> Result<(), AdminError> {
        match &self.store {
            AdminStore::Memory(store) => {
                let mut store = store
                    .lock()
                    .map_err(|_| AdminError::internal("admin store lock poisoned"))?;
                store.admins.remove(principal);
                store.admins.remove(&format!("user:{principal}"));
                store
                    .admins
                    .remove(&format!("email:{}", principal.to_lowercase()));
                Ok(())
            }
            AdminStore::Postgres(pool) => {
                sqlx::query(
                    r#"
                    DELETE FROM nebula_platform_admins
                    WHERE id = $1 OR user_id = $1 OR email = lower($1)
                    "#,
                )
                .bind(principal)
                .execute(pool)
                .await
                .map_err(|error| AdminError::internal(error.to_string()))?;
                Ok(())
            }
        }
    }

    async fn list_webhooks(&self) -> Result<Vec<TelemetryWebhookRecord>, AdminError> {
        match &self.store {
            AdminStore::Memory(store) => {
                let store = store
                    .lock()
                    .map_err(|_| AdminError::internal("admin store lock poisoned"))?;
                Ok(store.webhooks.values().cloned().collect())
            }
            AdminStore::Postgres(pool) => sqlx::query_as::<_, TelemetryWebhookRow>(
                r#"
                SELECT id, url, status, secret, created_at_unix_ms, updated_at_unix_ms,
                       last_delivery_status, last_delivery_at_unix_ms, last_error
                FROM nebula_admin_telemetry_webhooks
                ORDER BY created_at_unix_ms DESC
                "#,
            )
            .fetch_all(pool)
            .await
            .map(|rows| rows.into_iter().map(Into::into).collect())
            .map_err(|error| AdminError::internal(error.to_string())),
        }
    }

    async fn upsert_webhook(
        &self,
        mut record: TelemetryWebhookRecord,
    ) -> Result<TelemetryWebhookRecord, AdminError> {
        if record.status != "active" && record.status != "disabled" {
            return Err(AdminError::bad_request("status must be active or disabled"));
        }
        record.updated_at_unix_ms = unix_ms();
        match &self.store {
            AdminStore::Memory(store) => {
                let mut store = store
                    .lock()
                    .map_err(|_| AdminError::internal("admin store lock poisoned"))?;
                store.webhooks.insert(record.id.clone(), record.clone());
                Ok(record)
            }
            AdminStore::Postgres(pool) => {
                sqlx::query(
                    r#"
                    INSERT INTO nebula_admin_telemetry_webhooks (
                        id, url, status, secret, created_at_unix_ms, updated_at_unix_ms,
                        last_delivery_status, last_delivery_at_unix_ms, last_error
                    )
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                    ON CONFLICT (id) DO UPDATE SET
                        url = EXCLUDED.url,
                        status = EXCLUDED.status,
                        secret = EXCLUDED.secret,
                        updated_at_unix_ms = EXCLUDED.updated_at_unix_ms,
                        last_delivery_status = EXCLUDED.last_delivery_status,
                        last_delivery_at_unix_ms = EXCLUDED.last_delivery_at_unix_ms,
                        last_error = EXCLUDED.last_error
                    "#,
                )
                .bind(&record.id)
                .bind(&record.url)
                .bind(&record.status)
                .bind(&record.secret)
                .bind(record.created_at_unix_ms as i64)
                .bind(record.updated_at_unix_ms as i64)
                .bind(&record.last_delivery_status)
                .bind(record.last_delivery_at_unix_ms.map(|value| value as i64))
                .bind(&record.last_error)
                .execute(pool)
                .await
                .map_err(|error| AdminError::internal(error.to_string()))?;
                Ok(record)
            }
        }
    }

    async fn get_webhook(&self, id: &str) -> Result<TelemetryWebhookRecord, AdminError> {
        self.list_webhooks()
            .await?
            .into_iter()
            .find(|webhook| webhook.id == id)
            .ok_or_else(|| AdminError::not_found("telemetry webhook not found"))
    }

    async fn persist_telemetry_event(
        &self,
        event: &NebulaTelemetryEvent,
    ) -> Result<(), AdminError> {
        match &self.store {
            AdminStore::Memory(store) => {
                let mut store = store
                    .lock()
                    .map_err(|_| AdminError::internal("admin store lock poisoned"))?;
                store.telemetry_events.push(event.clone());
                if store.telemetry_events.len() > 500 {
                    store.telemetry_events.remove(0);
                }
                Ok(())
            }
            AdminStore::Postgres(pool) => {
                sqlx::query(
                    r#"
                    INSERT INTO nebula_admin_telemetry_events (
                        event_id, event_json, created_at_unix_ms
                    )
                    VALUES ($1, $2, $3)
                    ON CONFLICT (event_id) DO UPDATE SET event_json = EXCLUDED.event_json
                    "#,
                )
                .bind(&event.event_id)
                .bind(
                    serde_json::to_value(event)
                        .map_err(|error| AdminError::internal(error.to_string()))?,
                )
                .bind(event.created_at_unix_ms as i64)
                .execute(pool)
                .await
                .map_err(|error| AdminError::internal(error.to_string()))?;
                Ok(())
            }
        }
    }

    async fn stored_telemetry_events(&self) -> Result<Vec<NebulaTelemetryEvent>, AdminError> {
        let mut events = match &self.store {
            AdminStore::Memory(store) => {
                let store = store
                    .lock()
                    .map_err(|_| AdminError::internal("admin store lock poisoned"))?;
                store.telemetry_events.clone()
            }
            AdminStore::Postgres(pool) => {
                let values = sqlx::query_scalar::<_, Value>(
                    r#"
                    SELECT event_json
                    FROM nebula_admin_telemetry_events
                    ORDER BY created_at_unix_ms DESC
                    LIMIT 500
                    "#,
                )
                .fetch_all(pool)
                .await
                .map_err(|error| AdminError::internal(error.to_string()))?;
                values
                    .into_iter()
                    .filter_map(|value| serde_json::from_value(value).ok())
                    .collect()
            }
        };
        events.extend(read_telemetry_event_file(self.telemetry_event_file.as_ref()).await?);
        events.sort_by_key(|event| std::cmp::Reverse(event.created_at_unix_ms));
        events.dedup_by(|left, right| left.event_id == right.event_id);
        Ok(events)
    }
}

#[derive(sqlx::FromRow)]
struct PlatformAdminRow {
    id: String,
    user_id: Option<String>,
    email: Option<String>,
    role: String,
    status: String,
    created_at_unix_ms: i64,
    updated_at_unix_ms: i64,
    created_by: Option<String>,
    notes: Option<String>,
}

impl From<PlatformAdminRow> for PlatformAdminRecord {
    fn from(row: PlatformAdminRow) -> Self {
        Self {
            id: row.id,
            user_id: row.user_id,
            email: row.email,
            role: row.role,
            status: row.status,
            created_at_unix_ms: row.created_at_unix_ms as u64,
            updated_at_unix_ms: row.updated_at_unix_ms as u64,
            created_by: row.created_by,
            notes: row.notes,
        }
    }
}

#[derive(sqlx::FromRow)]
struct TelemetryWebhookRow {
    id: String,
    url: String,
    status: String,
    secret: Option<String>,
    created_at_unix_ms: i64,
    updated_at_unix_ms: i64,
    last_delivery_status: Option<String>,
    last_delivery_at_unix_ms: Option<i64>,
    last_error: Option<String>,
}

impl From<TelemetryWebhookRow> for TelemetryWebhookRecord {
    fn from(row: TelemetryWebhookRow) -> Self {
        Self {
            id: row.id,
            url: row.url,
            status: row.status,
            secret: row.secret,
            created_at_unix_ms: row.created_at_unix_ms as u64,
            updated_at_unix_ms: row.updated_at_unix_ms as u64,
            last_delivery_status: row.last_delivery_status,
            last_delivery_at_unix_ms: row.last_delivery_at_unix_ms.map(|value| value as u64),
            last_error: row.last_error,
        }
    }
}

#[derive(Deserialize)]
struct PlatformAdminUpsert {
    user_id: Option<String>,
    email: Option<String>,
    role: Option<String>,
    status: Option<String>,
    notes: Option<String>,
}

#[derive(Deserialize)]
struct TelemetryWebhookUpsert {
    url: String,
    status: Option<String>,
    secret: Option<String>,
}

#[derive(Deserialize)]
struct TelemetryQuery {
    limit: Option<usize>,
    severity: Option<String>,
    source: Option<String>,
    event_type: Option<String>,
    repository_id: Option<String>,
    since: Option<u64>,
}

async fn admin_health_live(
    State(state): State<AdminState>,
    headers: HeaderMap,
) -> Result<Json<Value>, AdminError> {
    let _admin = state.require_admin(&headers).await?;
    Ok(Json(json!({
        "status": "live",
        "checked_at_unix_ms": unix_ms(),
        "service": "nebula-registry",
        "admin_api": "enabled"
    })))
}

async fn admin_health_ready(
    State(state): State<AdminState>,
    headers: HeaderMap,
) -> Result<Json<Value>, AdminError> {
    let _admin = state.require_admin(&headers).await?;
    let report = health::ready_report(state.readiness.clone()).await;
    Ok(Json(json!({
        "status": report.status,
        "checked_at_unix_ms": report.checked_at_unix_ms,
        "dependencies": report.checks,
        "auth_provider": format!("{:?}", state.auth_provider),
        "telemetry_event_file": state.telemetry_event_file.as_ref().map(|path| path.display().to_string()),
    })))
}

async fn admin_metrics(
    State(state): State<AdminState>,
    headers: HeaderMap,
) -> Result<Json<health::MetricsJson>, AdminError> {
    let _admin = state.require_admin(&headers).await?;
    Ok(Json(state.metrics.snapshot().json()))
}

async fn list_telemetry_events(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Query(query): Query<TelemetryQuery>,
) -> Result<Json<Value>, AdminError> {
    let _admin = state.require_admin(&headers).await?;
    let mut events = state.stored_telemetry_events().await?;
    events.retain(|event| telemetry_matches(event, &query));
    let limit = query.limit.unwrap_or(100).clamp(1, 500);
    events.truncate(limit);
    Ok(Json(json!({ "events": events })))
}

async fn telemetry_summary(
    State(state): State<AdminState>,
    headers: HeaderMap,
) -> Result<Json<Value>, AdminError> {
    let _admin = state.require_admin(&headers).await?;
    let events = state.stored_telemetry_events().await?;
    let mut by_severity: BTreeMap<String, usize> = BTreeMap::new();
    let mut by_source: BTreeMap<String, usize> = BTreeMap::new();
    let mut by_type: BTreeMap<String, usize> = BTreeMap::new();
    for event in &events {
        *by_severity
            .entry(format!("{:?}", event.severity))
            .or_default() += 1;
        *by_source.entry(format!("{:?}", event.source)).or_default() += 1;
        *by_type.entry(event.event_type.clone()).or_default() += 1;
    }
    Ok(Json(json!({
        "total": events.len(),
        "by_severity": by_severity,
        "by_source": by_source,
        "by_type": by_type,
    })))
}

async fn ingest_telemetry_event(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(event): Json<NebulaTelemetryEvent>,
) -> Result<Json<Value>, AdminError> {
    let _admin = state.require_admin(&headers).await?;
    state.persist_telemetry_event(&event).await?;
    Ok(Json(
        json!({ "received": true, "event_id": event.event_id }),
    ))
}

async fn list_telemetry_webhooks(
    State(state): State<AdminState>,
    headers: HeaderMap,
) -> Result<Json<Value>, AdminError> {
    let _admin = state.require_admin(&headers).await?;
    let webhooks = state.list_webhooks().await?;
    Ok(Json(json!({ "webhooks": webhooks })))
}

async fn upsert_telemetry_webhook(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<TelemetryWebhookUpsert>,
) -> Result<Json<TelemetryWebhookRecord>, AdminError> {
    let _admin = state.require_admin(&headers).await?;
    let now = unix_ms();
    let record = TelemetryWebhookRecord {
        id,
        url: input.url,
        status: input.status.unwrap_or_else(|| "active".to_string()),
        secret: input.secret.or_else(|| state.webhook_secret.clone()),
        created_at_unix_ms: now,
        updated_at_unix_ms: now,
        last_delivery_status: None,
        last_delivery_at_unix_ms: None,
        last_error: None,
    };
    Ok(Json(state.upsert_webhook(record).await?))
}

async fn test_telemetry_webhook(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, AdminError> {
    let admin = state.require_admin(&headers).await?;
    let webhook = state.get_webhook(&id).await?;
    if webhook.status != "active" {
        return Err(AdminError::bad_request("telemetry webhook is disabled"));
    }
    let event = NebulaTelemetryEvent {
        event_id: format!("evt-admin-test-{}", unix_ms()),
        event_type: "telemetry.webhook.test".to_string(),
        source: TelemetrySource::Registry,
        severity: TelemetrySeverity::Info,
        message: "admin telemetry webhook test".to_string(),
        context: NebulaTelemetryContext {
            request_id: Some(admin.user_id),
            ..Default::default()
        },
        created_at_unix_ms: unix_ms(),
        attributes: BTreeMap::from([("webhook_id".to_string(), Value::String(webhook.id.clone()))]),
    };
    let delivery = deliver_webhook(&state, &webhook, &event).await;
    state.persist_telemetry_event(&event).await?;
    Ok(Json(json!({
        "event_id": event.event_id,
        "delivered": delivery.is_ok(),
        "error": delivery.err(),
    })))
}

async fn list_platform_admins(
    State(state): State<AdminState>,
    headers: HeaderMap,
) -> Result<Json<Value>, AdminError> {
    let _admin = state.require_admin(&headers).await?;
    Ok(Json(json!({ "admins": state.list_admins().await? })))
}

async fn upsert_platform_admin(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Path(principal): Path<String>,
    Json(input): Json<PlatformAdminUpsert>,
) -> Result<Json<PlatformAdminRecord>, AdminError> {
    let admin = state.require_admin(&headers).await?;
    let now = unix_ms();
    let is_email = principal.contains('@');
    let record = PlatformAdminRecord {
        id: if is_email {
            format!("email:{}", principal.to_lowercase())
        } else {
            format!("user:{principal}")
        },
        user_id: input
            .user_id
            .or_else(|| (!is_email).then_some(principal.clone())),
        email: input
            .email
            .or_else(|| is_email.then_some(principal.to_lowercase())),
        role: input.role.unwrap_or_else(|| "operator".to_string()),
        status: input.status.unwrap_or_else(|| "active".to_string()),
        created_at_unix_ms: now,
        updated_at_unix_ms: now,
        created_by: Some(admin.user_id),
        notes: input.notes,
    };
    Ok(Json(state.upsert_platform_admin_record(record).await?))
}

async fn delete_platform_admin(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Path(principal): Path<String>,
) -> Result<Json<Value>, AdminError> {
    let _admin = state.require_admin(&headers).await?;
    state.delete_platform_admin_record(&principal).await?;
    Ok(Json(json!({ "deleted": true })))
}

async fn read_telemetry_event_file(
    path: Option<&PathBuf>,
) -> Result<Vec<NebulaTelemetryEvent>, AdminError> {
    let Some(path) = path else {
        return Ok(Vec::new());
    };
    let content = match tokio::fs::read_to_string(path).await {
        Ok(content) => content,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(AdminError::internal(error.to_string())),
    };
    Ok(content
        .lines()
        .filter_map(|line| serde_json::from_str::<NebulaTelemetryEvent>(line).ok())
        .collect())
}

fn telemetry_matches(event: &NebulaTelemetryEvent, query: &TelemetryQuery) -> bool {
    if query
        .severity
        .as_ref()
        .is_some_and(|severity| *severity != format!("{:?}", event.severity))
    {
        return false;
    }
    if query
        .source
        .as_ref()
        .is_some_and(|source| *source != format!("{:?}", event.source))
    {
        return false;
    }
    if query
        .event_type
        .as_ref()
        .is_some_and(|event_type| event_type != &event.event_type)
    {
        return false;
    }
    if let Some(repository_id) = &query.repository_id {
        match event.context.repository_id.as_ref() {
            Some(id) if id.as_str() == repository_id => {}
            _ => return false,
        }
    }
    if query
        .since
        .is_some_and(|since| event.created_at_unix_ms < since)
    {
        return false;
    }
    true
}

async fn deliver_webhook(
    state: &AdminState,
    webhook: &TelemetryWebhookRecord,
    event: &NebulaTelemetryEvent,
) -> Result<(), String> {
    let body = serde_json::to_string(event).map_err(|error| error.to_string())?;
    let sent_at = unix_ms();
    let mut request = state
        .http_client
        .post(&webhook.url)
        .header("content-type", "application/json")
        .header("x-nebula-event-id", event.event_id.as_str())
        .header("x-nebula-sent-at", sent_at.to_string());
    if let Some(secret) = webhook.secret.as_ref().or(state.webhook_secret.as_ref()) {
        let digest = sha256_hex(&format!(
            "{}:{}:{}:{}",
            secret, event.event_id, sent_at, body
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

fn bearer_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn sha256_hex(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    hex::encode(hasher.finalize())
}

fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or_default()
}
