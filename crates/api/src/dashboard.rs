use axum::{Json, Router, extract::State, routing::{get, post}};

use crate::server::AppState;

/// Application settings stored in-memory and exposed via the dashboard API.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AppSettings {
    pub llm: LlmConfig,
    pub slack_webhook: String,
    pub discord_webhook: String,
    pub telegram_token: String,
    pub telegram_chat: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LlmConfig {
    pub endpoint: String,
    pub api_key: String,
    pub model: String,
    pub temperature: f64,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            llm: LlmConfig {
                endpoint: "https://api.openai.com/v1".into(),
                api_key: String::new(),
                model: "gpt-4".into(),
                temperature: 0.7,
            },
            slack_webhook: String::new(),
            discord_webhook: String::new(),
            telegram_token: String::new(),
            telegram_chat: String::new(),
        }
    }
}

/// Build the dashboard API sub-router. Routes are merged into the main router
/// in `server::create_router`.
pub fn dashboard_routes() -> Router<AppState> {
    Router::new()
        .route("/api/dashboard", get(get_dashboard_html))
        .route("/api/scope", get(get_scope).put(save_scope))
        .route("/api/stats", get(get_stats))
        .route("/api/settings", get(get_settings).put(save_settings))
        .route("/api/scans", get(list_dashboard_scans))
        .route("/api/scan", post(start_dashboard_scan))
        .route("/api/findings", get(list_dashboard_findings))
        .route("/api/graph", get(get_dashboard_graph))
}

/// Serve the embedded dashboard HTML.
pub async fn get_dashboard_html() -> (axum::http::StatusCode, axum::response::Html<&'static str>) {
    (axum::http::StatusCode::OK, axum::response::Html(include_str!("../static/dashboard.html")))
}

/// GET /api/scope — return current scope config.
async fn get_scope(State(state): State<AppState>) -> Json<serde_json::Value> {
    let scope = state.scope.lock().unwrap();
    Json(serde_json::json!({
        "in_scope": scope.in_scope,
        "out_of_scope": scope.out_of_scope,
    }))
}

#[derive(serde::Deserialize)]
struct ScopeUpdate {
    in_scope: Vec<String>,
    out_of_scope: Vec<String>,
}

/// PUT /api/scope — update scope config.
async fn save_scope(
    State(state): State<AppState>,
    Json(update): Json<ScopeUpdate>,
) -> Json<serde_json::Value> {
    let mut scope = state.scope.lock().unwrap();
    scope.in_scope = update.in_scope;
    scope.out_of_scope = update.out_of_scope;
    Json(serde_json::json!({"status": "saved"}))
}

/// GET /api/stats — aggregate scan/finding statistics.
/// Queries the database for real counts when available.
async fn get_stats(State(state): State<AppState>) -> Json<serde_json::Value> {
    let total_scans = state.db.list_scans()
        .map(|s| s.len() as u64)
        .unwrap_or(0);

    let all_findings = state.db.get_all_findings()
        .unwrap_or_default();

    let findings_count = all_findings.len();

    let severity_counts = || -> (usize, usize, usize, usize, usize) {
        let mut c = (0usize, 0, 0, 0, 0);
        for f in &all_findings {
            match f.severity {
                aegis_core::types::Severity::Critical => c.0 += 1,
                aegis_core::types::Severity::High => c.1 += 1,
                aegis_core::types::Severity::Medium => c.2 += 1,
                aegis_core::types::Severity::Low => c.3 += 1,
                aegis_core::types::Severity::Info => c.4 += 1,
            }
        }
        c
    };
    let (critical, high, medium, low, info) = severity_counts();

    Json(serde_json::json!({
        "total_scans": total_scans,
        "total_findings": findings_count,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "info": info,
        "domains": 0,
    }))
}

/// GET /api/settings — return current settings.
async fn get_settings(State(state): State<AppState>) -> Json<serde_json::Value> {
    let settings = state.settings.lock().unwrap();
    Json(serde_json::json!(&*settings))
}

/// PUT /api/settings — update settings.
async fn save_settings(
    State(state): State<AppState>,
    Json(update): Json<AppSettings>,
) -> Json<serde_json::Value> {
    let mut settings = state.settings.lock().unwrap();
    *settings = update;
    Json(serde_json::json!({"status": "saved"}))
}

/// GET /api/scans — list all scans with finding counts and duration.
async fn list_dashboard_scans(State(state): State<AppState>) -> Json<serde_json::Value> {
    let scans = state.db.list_scans().unwrap_or_default();
    let scans_json: Vec<serde_json::Value> = scans.into_iter().map(|s| {
        let count = state.db.get_findings_by_scan(&s.id)
            .map(|f| f.len())
            .unwrap_or(0);
        serde_json::json!({
            "id": s.id,
            "target": s.target,
            "status": s.status,
            "started_at": s.started_at,
            "completed_at": s.completed_at,
            "duration": s.duration_secs,
            "finding_count": count,
        })
    }).collect();
    Json(serde_json::json!({"scans": scans_json}))
}

/// POST /api/scan — start a new scan via the dashboard.
async fn start_dashboard_scan(
    State(state): State<AppState>,
    Json(req): Json<super::server::ScanRequest>,
) -> Json<serde_json::Value> {
    // Reuse the existing start_scan logic
    super::server::handle_start_scan(state, req).await
}

/// GET /api/findings — return all findings across all scans.
async fn list_dashboard_findings(State(state): State<AppState>) -> Json<serde_json::Value> {
    let findings = state.db.get_all_findings().unwrap_or_default();
    Json(serde_json::json!({"findings": findings}))
}

/// GET /api/graph — return attack graph data (nodes + edges + chains).
async fn get_dashboard_graph(State(state): State<AppState>) -> Json<serde_json::Value> {
    let graph = aegis_graph::graph::AttackGraph::new();
    let json = graph.export_json();

    // Extract nodes and edges from the graph JSON for table display
    let nodes: Vec<serde_json::Value> = json.get("nodes")
        .and_then(|n| n.as_array())
        .map(|arr| arr.iter().map(|n| serde_json::json!({
            "id": n.get("id"),
            "type": n.get("type"),
            "label": n.get("label"),
        })).collect())
        .unwrap_or_default();

    let edges: Vec<serde_json::Value> = json.get("edges")
        .and_then(|e| e.as_array())
        .map(|arr| arr.iter().map(|e| serde_json::json!({
            "source": e.get("source"),
            "target": e.get("target"),
            "type": e.get("type"),
        })).collect())
        .unwrap_or_default();

    // Build chains from findings
    let findings = state.db.get_all_findings().unwrap_or_default();
    let mut chains: Vec<String> = Vec::new();
    if findings.len() >= 2 {
        for i in 0..findings.len().saturating_sub(1) {
            let chain = format!("{} \u{2192} {}", findings[i].title, findings[i + 1].title);
            chains.push(chain);
        }
    }

    Json(serde_json::json!({
        "nodes": nodes,
        "edges": edges,
        "chains": chains,
        "raw": json,
    }))
}
