use axum::{
    Router,
    Json,
    extract::{Path, State},
    routing::{get, post},
    response::sse::{Event as SseEvent, Sse},
};
use std::sync::{Arc, Mutex};
use std::convert::Infallible;
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;

use aegis_core::types::ScanReport;
use aegis_core::target::{TargetValidator, ScopeConfig};
use aegis_core::config::AppConfig;
use aegis_events::bus::EventBus;
use aegis_events::types::Event;
use aegis_recon::registry::PluginRegistry;
use aegis_scheduler::engine::SchedulerEngine;
use aegis_storage::db::Database;
use aegis_reporting::markdown::MarkdownReport;
use aegis_graph::graph::AttackGraph;

use crate::dashboard;

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Database>,
    pub event_bus: EventBus,
    pub config: AppConfig,
    pub scope: Arc<Mutex<ScopeConfig>>,
    pub settings: Arc<Mutex<dashboard::AppSettings>>,
}

pub fn create_router(state: AppState) -> Router {
    // Main API routes
    let api_router = Router::new()
        .route("/health", get(health))
        .route("/scan", post(start_scan))
        .route("/scan/{id}", get(get_scan))
        .route("/scans", get(list_scans))
        .route("/scan/{id}/report", get(get_report))
        .route("/scan/{id}/graph", get(get_graph))
        .route("/scan/{id}/events", get(stream_events));

    // Dashboard routes (merged into the same router with the same state)
    let dash_router = dashboard::dashboard_routes();

    Router::new()
        .merge(api_router)
        .merge(dash_router)
        .with_state(state)
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({"status": "ok", "version": "0.1.0"}))
}

#[derive(serde::Deserialize)]
pub struct ScanRequest {
    pub target: String,
}

async fn start_scan(
    State(state): State<AppState>,
    Json(req): Json<ScanRequest>,
) -> Json<serde_json::Value> {
    handle_start_scan(state, req).await
}

/// Shared scan-start logic used by both the main `/scan` route and the
/// dashboard `/api/scan` route.
pub async fn handle_start_scan(
    state: AppState,
    req: ScanRequest,
) -> Json<serde_json::Value> {
    let parsed = match TargetValidator::parse(&req.target) {
        Ok(t) => t,
        Err(e) => return Json(serde_json::json!({"error": e.to_string()})),
    };

    let target = parsed.normalized.clone();
    let scan_id = uuid::Uuid::new_v4().to_string();

    // Spawn the scan in a background task to avoid Send/Sync constraints
    let db = state.db.clone();
    let event_bus = state.event_bus.clone();
    let config = state.config.clone();
    tokio::spawn(async move {
        let registry = PluginRegistry::new();
        let engine = SchedulerEngine::new(config, event_bus, db, registry);
        match engine.run_scan(&target).await {
            Ok(_sid) => tracing::info!("[api] Scan {} completed for target {}", _sid, target),
            Err(e) => tracing::error!("[api] Scan failed for target {}: {}", target, e),
        }
    });

    Json(serde_json::json!({
        "scan_id": scan_id,
        "target": parsed.normalized,
        "status": "running"
    }))
}

async fn get_scan(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Json<serde_json::Value> {
    match state.db.get_findings_by_scan(&id) {
        Ok(findings) => Json(serde_json::json!({
            "scan_id": id,
            "finding_count": findings.len(),
            "findings": findings,
        })),
        Err(e) => Json(serde_json::json!({"error": e.to_string()})),
    }
}

async fn list_scans(
    State(_state): State<AppState>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({"scans": [], "message": "Use /scan/{id} to query specific scans"}))
}

async fn get_report(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Json<serde_json::Value> {
    match state.db.get_findings_by_scan(&id) {
        Ok(findings) => {
            let services = state.db.get_services_by_scan(&id).unwrap_or_default();
            let report = ScanReport {
                target: format!("scan-{}", id),
                scan_id: id.clone(),
                started_at: chrono::Utc::now(),
                completed_at: Some(chrono::Utc::now()),
                duration_secs: None,
                domains: vec![],
                subdomains: vec![],
                services,
                technologies: vec![],
                endpoints: vec![],
                findings,
                exploit_refs: vec![],
            };
            let markdown = MarkdownReport::generate(&report);
            Json(serde_json::json!({"report": markdown, "scan_id": id}))
        }
        Err(e) => Json(serde_json::json!({"error": e.to_string()})),
    }
}

async fn get_graph(
    State(_state): State<AppState>,
    Path(id): Path<String>,
) -> Json<serde_json::Value> {
    let graph = AttackGraph::new();
    // Build from stored data (simplified for now)
    let json = graph.export_json();
    Json(serde_json::json!({
        "scan_id": id,
        "graph": json,
        "message": "Full graph: query /scan/{id}/findings for node data"
    }))
}

async fn stream_events(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Sse<impl tokio_stream::Stream<Item = Result<SseEvent, Infallible>>> {
    let rx: broadcast::Receiver<Event> = state.event_bus.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(move |result| {
        match result {
            Ok(event) => {
                // Only emit events for this scan
                if event.scan_id() == Some(&id) || id == "all" {
                    let data = serde_json::to_string(&event).unwrap_or_default();
                    Some(Ok(SseEvent::default().data(data)))
                } else {
                    None
                }
            }
            Err(_) => None,
        }
    });
    Sse::new(stream)
}
