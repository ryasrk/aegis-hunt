use aegis_core::config::AppConfig;
use aegis_core::error::AegisResult;
use aegis_events::bus::EventBus;
use aegis_events::types::Event;
use aegis_recon::registry::PluginRegistry;
use aegis_storage::db::Database;
use chrono::Utc;
use std::sync::Arc;
use tracing::{info, error};

/// The central orchestrator for Aegis scanning phases.
pub struct SchedulerEngine {
    #[allow(dead_code)]
    config: AppConfig,
    event_bus: EventBus,
    db: Arc<Database>,
    registry: PluginRegistry,
}

impl SchedulerEngine {
    pub fn new(
        config: AppConfig,
        event_bus: EventBus,
        db: Arc<Database>,
        registry: PluginRegistry,
    ) -> Self {
        Self { config, event_bus, db, registry }
    }

    /// Run the full Aegis scan pipeline against a target.
    ///
    /// Currently implements Phase 1 (Recon). More phases will be added.
    pub async fn run_scan(&self, target: &str) -> AegisResult<String> {
        let scan_id = self.db.create_scan(target)?;
        let now = Utc::now();

        self.event_bus.emit(Event::ScanStarted {
            scan_id: scan_id.clone(),
            target: target.to_string(),
            timestamp: now,
        }).ok();

        info!("[{}] Starting scan on target: {}", scan_id, target);

        // Phase 1: Reconnaissance
        self.event_bus.emit(Event::PhaseStarted {
            scan_id: scan_id.clone(),
            phase: "recon".into(),
            timestamp: Utc::now(),
        }).ok();

        if let Some(subfinder) = self.registry.get("subfinder") {
            match subfinder.execute(target, &scan_id) {
                Ok(subdomains) => {
                    for sub in &subdomains {
                        let _ = self.db.insert_subdomain(&scan_id, sub, "subfinder");
                        self.event_bus.emit(Event::SubdomainDiscovered {
                            scan_id: scan_id.clone(),
                            subdomain: sub.clone(),
                            source: "subfinder".into(),
                            timestamp: Utc::now(),
                        }).ok();
                    }
                    info!("[{}] Found {} subdomains", scan_id, subdomains.len());
                }
                Err(e) => error!("[{}] Subfinder error: {}", scan_id, e),
            }
        }

        if let Some(httpx) = self.registry.get("httpx") {
            match httpx.execute(target, &scan_id) {
                Ok(results) => {
                    for line in &results {
                        match serde_json::from_str::<serde_json::Value>(line) {
                            Ok(parsed) => {
                                let url = parsed.get("url").and_then(|v| v.as_str()).unwrap_or(target);
                                let status = parsed.get("status_code").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
                                let title = parsed.get("title").and_then(|v| v.as_str()).map(|s| s.to_string());
                                let tech: Vec<String> = parsed.get("tech")
                                    .and_then(|v| v.as_array())
                                    .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                                    .unwrap_or_default();

                                let _ = self.db.insert_service(&scan_id, "", url, status, title.as_deref(), &tech);

                                self.event_bus.emit(Event::HttpServiceDetected {
                                    scan_id: scan_id.clone(),
                                    url: url.to_string(),
                                    status_code: status,
                                    title,
                                    tech,
                                    timestamp: Utc::now(),
                                }).ok();
                            }
                            Err(_) => {
                                tracing::warn!("[{}] Skipping non-JSON httpx line: {}", scan_id, line);
                            }
                        }
                    }
                    info!("[{}] Httpx scanned {} services", scan_id, results.len());
                }
                Err(e) => error!("[{}] Httpx error: {}", scan_id, e),
            }
        }

        self.event_bus.emit(Event::PhaseCompleted {
            scan_id: scan_id.clone(),
            phase: "recon".into(),
            timestamp: Utc::now(),
        }).ok();

        self.event_bus.emit(Event::ScanCompleted {
            scan_id: scan_id.clone(),
            timestamp: Utc::now(),
        }).ok();

        self.db.complete_scan(&scan_id)?;
        info!("[{}] Scan completed", scan_id);

        Ok(scan_id)
    }

    /// Access the event bus for subscribing to events.
    pub fn event_bus(&self) -> &EventBus {
        &self.event_bus
    }

    /// Access the database for querying results.
    pub fn db(&self) -> &Database {
        &self.db
    }
}
