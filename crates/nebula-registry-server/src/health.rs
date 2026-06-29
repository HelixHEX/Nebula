use axum::{Json, http::StatusCode, response::IntoResponse};
use nebula_storage::{ObjectBlobStore, PgVectorManifestStore, PostgresMetadataStore};
use serde::Serialize;
use std::time::Instant;

#[derive(Clone, Debug, Serialize)]
pub struct Probe {
    pub status: String,
    pub checks: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct DependencyProbe {
    pub name: String,
    pub status: String,
    pub latency_ms: u128,
    pub detail: String,
    pub checked_at_unix_ms: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct DetailedProbe {
    pub status: String,
    pub checked_at_unix_ms: u64,
    pub checks: Vec<DependencyProbe>,
}

#[derive(Clone, Debug, Default)]
pub struct ReadinessState {
    pub postgres_url: Option<String>,
    pub blob_store_url: Option<String>,
    pub vector_store_url: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct MetricsSnapshot {
    pub requests_total: u64,
    pub responses_total: u64,
    pub rate_limited_total: u64,
    pub server_errors_total: u64,
    pub auth_failures_total: u64,
    pub cas_conflicts_total: u64,
    pub vector_requests_total: u64,
    pub deploy_handoffs_total: u64,
    pub deploy_callbacks_total: u64,
    pub latency_micros_total: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct MetricsJson {
    pub up: u8,
    pub requests_total: u64,
    pub responses_total: u64,
    pub rate_limited_total: u64,
    pub server_errors_total: u64,
    pub auth_failures_total: u64,
    pub cas_conflicts_total: u64,
    pub vector_requests_total: u64,
    pub deploy_handoffs_total: u64,
    pub deploy_callbacks_total: u64,
    pub latency_micros_total: u64,
    pub average_latency_micros: u64,
}

impl MetricsSnapshot {
    pub fn json(&self) -> MetricsJson {
        MetricsJson {
            up: 1,
            requests_total: self.requests_total,
            responses_total: self.responses_total,
            rate_limited_total: self.rate_limited_total,
            server_errors_total: self.server_errors_total,
            auth_failures_total: self.auth_failures_total,
            cas_conflicts_total: self.cas_conflicts_total,
            vector_requests_total: self.vector_requests_total,
            deploy_handoffs_total: self.deploy_handoffs_total,
            deploy_callbacks_total: self.deploy_callbacks_total,
            latency_micros_total: self.latency_micros_total,
            average_latency_micros: self
                .latency_micros_total
                .checked_div(self.responses_total)
                .unwrap_or_default(),
        }
    }
}

pub async fn live() -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(Probe {
            status: "live".to_string(),
            checks: Vec::new(),
        }),
    )
}

pub async fn metrics(snapshot: MetricsSnapshot) -> impl IntoResponse {
    (
        StatusCode::OK,
        format!(
            "nebula_registry_up 1\nnebula_registry_requests_total {}\nnebula_registry_responses_total {}\nnebula_registry_rate_limited_total {}\nnebula_registry_server_errors_total {}\nnebula_registry_auth_failures_total {}\nnebula_registry_cas_conflicts_total {}\nnebula_registry_vector_requests_total {}\nnebula_registry_deploy_handoffs_total {}\nnebula_registry_deploy_callbacks_total {}\nnebula_registry_latency_micros_total {}\n",
            snapshot.requests_total,
            snapshot.responses_total,
            snapshot.rate_limited_total,
            snapshot.server_errors_total,
            snapshot.auth_failures_total,
            snapshot.cas_conflicts_total,
            snapshot.vector_requests_total,
            snapshot.deploy_handoffs_total,
            snapshot.deploy_callbacks_total,
            snapshot.latency_micros_total
        ),
    )
}

pub async fn ready(state: ReadinessState) -> impl IntoResponse {
    let report = ready_report(state).await;
    let checks = report
        .checks
        .iter()
        .map(|check| {
            if check.status == "ok" {
                format!("{}:ok", check.name)
            } else {
                format!("{}:{}", check.name, check.detail)
            }
        })
        .collect::<Vec<_>>();
    if report.status != "ready" {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(Probe {
                status: "not_ready".to_string(),
                checks,
            }),
        );
    }
    (
        StatusCode::OK,
        Json(Probe {
            status: "ready".to_string(),
            checks,
        }),
    )
}

pub async fn ready_report(state: ReadinessState) -> DetailedProbe {
    let mut checks = Vec::new();

    if let Some(url) = &state.postgres_url {
        let started = Instant::now();
        match PostgresMetadataStore::connect(url).await {
            Ok(store) => match store.ready().await {
                Ok(()) => checks.push(dependency("postgres", "ok", "connected", started)),
                Err(error) => {
                    checks.push(dependency(
                        "postgres",
                        "not_ready",
                        error.to_string(),
                        started,
                    ));
                    return detailed_probe("not_ready", checks);
                }
            },
            Err(error) => {
                checks.push(dependency(
                    "postgres",
                    "not_ready",
                    error.to_string(),
                    started,
                ));
                return detailed_probe("not_ready", checks);
            }
        }
    }

    if let Some(url) = &state.blob_store_url {
        let started = Instant::now();
        match ObjectBlobStore::from_url(url) {
            Ok(store) => match store.ready().await {
                Ok(()) => checks.push(dependency("blob_store", "ok", "connected", started)),
                Err(error) => {
                    checks.push(dependency(
                        "blob_store",
                        "not_ready",
                        error.to_string(),
                        started,
                    ));
                    return detailed_probe("not_ready", checks);
                }
            },
            Err(error) => {
                checks.push(dependency(
                    "blob_store",
                    "not_ready",
                    error.to_string(),
                    started,
                ));
                return detailed_probe("not_ready", checks);
            }
        }
    }

    if let Some(url) = &state.vector_store_url {
        let started = Instant::now();
        match PgVectorManifestStore::connect(url).await {
            Ok(store) => match store.ready().await {
                Ok(()) => checks.push(dependency("vector_store", "ok", "connected", started)),
                Err(error) => {
                    checks.push(dependency(
                        "vector_store",
                        "not_ready",
                        error.to_string(),
                        started,
                    ));
                    return detailed_probe("not_ready", checks);
                }
            },
            Err(error) => {
                checks.push(dependency(
                    "vector_store",
                    "not_ready",
                    error.to_string(),
                    started,
                ));
                return detailed_probe("not_ready", checks);
            }
        }
    }

    detailed_probe("ready", checks)
}

fn dependency(
    name: impl Into<String>,
    status: impl Into<String>,
    detail: impl Into<String>,
    started: Instant,
) -> DependencyProbe {
    DependencyProbe {
        name: name.into(),
        status: status.into(),
        latency_ms: started.elapsed().as_millis(),
        detail: detail.into(),
        checked_at_unix_ms: unix_ms(),
    }
}

fn detailed_probe(status: impl Into<String>, checks: Vec<DependencyProbe>) -> DetailedProbe {
    DetailedProbe {
        status: status.into(),
        checked_at_unix_ms: unix_ms(),
        checks,
    }
}

fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or_default()
}
