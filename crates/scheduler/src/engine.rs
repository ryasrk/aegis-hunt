use aegis_core::config::AppConfig;
use aegis_core::error::AegisResult;
use aegis_events::bus::EventBus;
use aegis_events::types::Event;
use aegis_jsengine::downloader::JsDownloader;
use aegis_jsengine::extractor::JsExtractor;
use aegis_recon::registry::PluginRegistry;
use aegis_storage::db::Database;
use std::io::Write;
use std::sync::Arc;
use tracing::{info, error};

use crate::notify::Notifier;
use crate::queue::{PriorityQueue, QueueItem, QueuePriority};

/// Simple progress logging to `recon/<scan_id>/progress.log`.
fn log_progress(scan_id: &str, phase: &str, message: &str) {
    let dir = format!("recon/{}", scan_id);
    let _ = std::fs::create_dir_all(&dir);
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(format!("{}/progress.log", dir))
    {
        let _ = writeln!(
            file,
            "[{}] {}: {}",
            chrono::Utc::now().format("%H:%M:%S"),
            phase,
            message
        );
    }
}

/// The central orchestrator for Aegis scanning phases.
pub struct SchedulerEngine {
    #[allow(dead_code)]
    config: AppConfig,
    event_bus: EventBus,
    db: Arc<Database>,
    registry: PluginRegistry,
    queue: PriorityQueue,
}

impl SchedulerEngine {
    pub fn new(
        config: AppConfig,
        event_bus: EventBus,
        db: Arc<Database>,
        registry: PluginRegistry,
    ) -> Self {
        Self {
            config,
            event_bus,
            db,
            registry,
            queue: PriorityQueue::new(),
        }
    }

    /// Access the priority queue.
    pub fn queue(&self) -> &PriorityQueue {
        &self.queue
    }

    /// Run the full Aegis scan pipeline against a target.
    ///
    /// Enqueues tasks and processes them via the priority queue.
    pub async fn run_scan(&self, target: &str) -> AegisResult<String> {
        let start = std::time::Instant::now();
        let scan_id = self.db.create_scan(target)?;

        log_progress(&scan_id, "init", &format!("Starting scan on target: {}", target));

        self.event_bus.emit(Event::ScanStarted {
            scan_id: scan_id.clone(),
            target: target.to_string(),
            timestamp: chrono::Utc::now(),
        }).ok();

        info!("[{}] Starting scan on target: {}", scan_id, target);

        // Enqueue subdomain enumeration (Fast priority)
        self.queue.enqueue(QueueItem::new(
            "subdomain_enum",
            target,
            QueuePriority::Fast,
        ));

        // Enqueue HTTP probing (Fast priority)
        self.queue.enqueue(QueueItem::new(
            "http_probe",
            target,
            QueuePriority::Fast,
        ));

        log_progress(&scan_id, "queue", "Enqueued subdomain_enum and http_probe tasks");

        // Process the queue (up to 20 items)
        let processed = self.process_queue(20).await?;

        let duration = start.elapsed().as_secs();
        log_progress(&scan_id, "complete", &format!("Scan completed in {}s, processed {} items", duration, processed));

        self.event_bus.emit(Event::ScanCompleted {
            scan_id: scan_id.clone(),
            timestamp: chrono::Utc::now(),
            duration_secs: duration,
        }).ok();

        self.db.complete_scan(&scan_id)?;
        info!("[{}] Scan completed in {}s, processed {} queue items", scan_id, duration, processed);
        Ok(scan_id)
    }

    /// Process items from the priority queue in a background task.
    pub async fn process_queue(&self, max_items: usize) -> AegisResult<usize> {
        let mut processed = 0;
        for _ in 0..max_items {
            let item = match self.queue.dequeue() {
                Some(item) => item,
                None => break, // queue empty
            };

            match item.task_type.as_str() {
                "subdomain_enum" => {
                    log_progress(&item.id, "recon", &format!("Subdomain enumeration on {}", item.target));
                    // Run SubfinderPlugin
                    if let Some(plugin) = self.registry.get("subfinder") {
                        match plugin.execute(&item.target, &item.id) {
                            Ok(subdomains) => {
                                for sub in &subdomains {
                                    let _ = self.db.insert_subdomain(&item.id, sub, "subfinder");
                                    self.event_bus.emit(
                                        Event::SubdomainDiscovered {
                                            scan_id: item.id.clone(),
                                            subdomain: sub.clone(),
                                            source: "subfinder".into(),
                                            timestamp: chrono::Utc::now(),
                                        }
                                    ).ok();
                                }
                                log_progress(&item.id, "recon", &format!("Found {} subdomains", subdomains.len()));
                            }
                            Err(e) => error!("Subfinder error: {}", e),
                        }
                    }
                }
                "http_probe" => {
                    log_progress(&item.id, "probe", &format!("HTTP probing on {}", item.target));
                    // Run HttpxPlugin
                    if let Some(plugin) = self.registry.get("httpx") {
                        match plugin.execute(&item.target, &item.id) {
                            Ok(results) => {
                                let mut js_urls: Vec<String> = Vec::new();
                                for line in &results {
                                    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(line) {
                                        let url = parsed.get("url").and_then(|v| v.as_str()).unwrap_or(&item.target);
                                        let status = parsed.get("status_code").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
                                        let title = parsed.get("title").and_then(|v| v.as_str()).map(|s| s.to_string());
                                        let tech: Vec<String> = parsed.get("tech")
                                            .and_then(|v| v.as_array())
                                            .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                                            .unwrap_or_default();
                                        let _ = self.db.insert_service(&item.id, "", url, status, title.as_deref(), &tech);

                                        // Check content type for JS
                                        let content_type = parsed.get("content_type")
                                            .and_then(|v| v.as_str()).unwrap_or("");

                                        // Enqueue JS analysis for URLs that could contain JS
                                        if content_type.contains("javascript") || content_type.contains("html") || tech.iter().any(|t| t == "react" || t == "vue" || t == "angular" || t == "nextjs" || t == "nuxtjs") {
                                            self.queue.enqueue(
                                                QueueItem::new("js_analysis", url.to_string(), QueuePriority::Medium)
                                            );
                                        }
                                        js_urls.push(url.to_string());
                                    }
                                }

                                // Also enqueue JS discovery for the main target page
                                self.queue.enqueue(
                                    QueueItem::new("js_analysis", item.target.to_string(), QueuePriority::Medium)
                                );
                                log_progress(&item.id, "probe", &format!("Probed {} services", results.len()));
                            }
                            Err(e) => error!("Httpx error: {}", e),
                        }
                    }
                }
                "vuln_scan" => {
                    log_progress(&item.id, "vuln", &format!("Vulnerability scan on {}", item.target));
                    if let Some(plugin) = self.registry.get("nuclei") {
                        match plugin.execute(&item.target, &item.id) {
                            Ok(results) => {
                                info!("[{}] nuclei found {} hits", item.id, results.len());
                                log_progress(&item.id, "vuln", &format!("Found {} vulnerabilities", results.len()));
                                for result in &results {
                                    Notifier::on_finding(&item.id, "MEDIUM", result, &item.target);
                                }
                            }
                            Err(e) => error!("Nuclei error: {}", e),
                        }
                    }
                }
                "js_analysis" => {
                    log_progress(&item.id, "js", &format!("JS analysis on {}", item.target));
                    let downloader = JsDownloader::new();
                    let extractor = JsExtractor::new();

                    match downloader.download(&item.target).await {
                        Ok(content) => {
                            // First try to discover JS URLs from HTML
                            let js_urls = downloader.discover_js_urls(&content, &item.target);

                            // Extract findings from the HTML itself (may contain inline JS or embedded paths)
                            let findings = extractor.extract_all(&content, &item.target);
                            for f in &findings {
                                self.event_bus.emit(Event::SecretDetected {
                                    scan_id: item.id.clone(),
                                    url: item.target.clone(),
                                    secret_type: f.extract_type.clone(),
                                    context: f.value.clone(),
                                    timestamp: chrono::Utc::now(),
                                }).ok();
                                Notifier::on_finding(&item.id, "HIGH", &f.extract_type, &item.target);
                            }

                            // Also download and analyze each discovered JS file
                            for js_url in &js_urls {
                                match downloader.download(js_url).await {
                                    Ok(js_content) => {
                                        let js_findings = extractor.extract_all(&js_content, js_url);
                                        for f in &js_findings {
                                            self.event_bus.emit(Event::SecretDetected {
                                                scan_id: item.id.clone(),
                                                url: js_url.clone(),
                                                secret_type: f.extract_type.clone(),
                                                context: f.value.clone(),
                                                timestamp: chrono::Utc::now(),
                                            }).ok();
                                            Notifier::on_finding(&item.id, "HIGH", &f.extract_type, js_url);
                                        }
                                        info!("[{}] JS analysis of {} found {} items", item.id, js_url, js_findings.len());
                                    }
                                    Err(e) => tracing::warn!("[{}] Failed to download JS {}: {}", item.id, js_url, e),
                                }
                            }
                            info!("[{}] JS analysis of {} found {} direct + {} JS files", item.id, item.target, findings.len(), js_urls.len());
                            log_progress(&item.id, "js", &format!("Found {} secrets in JS", findings.len()));
                        }
                        Err(e) => {
                            // Non-HTML pages or unavailable will fail here — that's OK
                            tracing::debug!("[{}] No JS content at {}: {}", item.id, item.target, e);
                        }
                    }
                }
                _ => {
                    tracing::warn!("Unknown task type: {}", item.task_type);
                    log_progress(&item.id, "error", &format!("Unknown task type: {}", item.task_type));
                }
            }
            processed += 1;
        }
        Ok(processed)
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
