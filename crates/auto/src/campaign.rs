use std::sync::Arc;
use chrono::{DateTime, Utc};
use aegis_core::config::AppConfig;
use aegis_core::error::AegisResult;
use aegis_core::types::ScanReport;
use aegis_events::bus::EventBus;
use aegis_recon::registry::PluginRegistry;
use aegis_scheduler::engine::SchedulerEngine;
use aegis_storage::db::Database;
use aegis_reporting::markdown::MarkdownReport;
use aegis_graph::graph::AttackGraph;
use aegis_graph::risk::calculate_risk;

#[derive(Debug, Clone, serde::Serialize)]
pub struct CampaignState {
    pub id: String,
    pub target: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub phases: CampaignPhases,
    pub findings_count: usize,
    pub risk_score: u32,
    pub status: CampaignStatus,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CampaignPhases {
    pub recon: PhaseStatus,
    pub verify: PhaseStatus,
    pub hunter: PhaseStatus,
    pub exploit: PhaseStatus,
    pub report: PhaseStatus,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct PhaseStatus {
    pub completed: bool,
    pub items_found: usize,
    pub duration_secs: u64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub enum CampaignStatus {
    Running,
    Completed,
    Failed(String),
}

pub struct CampaignEngine {
    config: AppConfig,
    event_bus: EventBus,
    db: Arc<Database>,
}

impl CampaignEngine {
    pub fn new(config: AppConfig, event_bus: EventBus, db: Arc<Database>) -> Self {
        Self { config, event_bus, db }
    }

    /// Run the full autonomous campaign against a target.
    /// Executes all phases: recon -> verify -> hunter -> exploit -> report.
    pub async fn run(&self, target: &str) -> AegisResult<CampaignState> {
        let campaign_id = uuid::Uuid::new_v4().to_string();
        let started_at = Utc::now();
        let start = std::time::Instant::now();
        let mut phases = CampaignPhases {
            recon: PhaseStatus { completed: false, items_found: 0, duration_secs: 0 },
            verify: PhaseStatus { completed: false, items_found: 0, duration_secs: 0 },
            hunter: PhaseStatus { completed: false, items_found: 0, duration_secs: 0 },
            exploit: PhaseStatus { completed: false, items_found: 0, duration_secs: 0 },
            report: PhaseStatus { completed: false, items_found: 0, duration_secs: 0 },
        };

        tracing::info!("[{}] Starting autonomous campaign on {}", campaign_id, target);

        // Phase 1: Recon
        let scan_id = {
            let phase_start = std::time::Instant::now();
            let registry = PluginRegistry::new();
            let engine = SchedulerEngine::new(
                self.config.clone(),
                self.event_bus.clone(),
                self.db.clone(),
                registry,
            );
            let sid = engine.run_scan(target).await?;
            phases.recon = PhaseStatus {
                completed: true,
                items_found: self.db.get_services_by_scan(&sid).unwrap_or_default().len(),
                duration_secs: phase_start.elapsed().as_secs(),
            };
            tracing::info!("[{}] Recon complete: {} services found", campaign_id, phases.recon.items_found);
            sid
        };

        // Phase 2: Hunter Intelligence
        {
            let phase_start = std::time::Instant::now();
            let services = self.db.get_services_by_scan(&scan_id).unwrap_or_default();
            let urls: Vec<String> = services.iter().map(|s| s.url.clone()).collect();
            let classified = aegis_hunter::endpoints::classify_all(&urls);
            phases.hunter = PhaseStatus {
                completed: true,
                items_found: classified.len(),
                duration_secs: phase_start.elapsed().as_secs(),
            };
            tracing::info!("[{}] Hunter analysis: {} endpoints classified", campaign_id, classified.len());
        }

        // Phase 3: Verify
        {
            let phase_start = std::time::Instant::now();
            let findings = self.db.get_findings_by_scan(&scan_id).unwrap_or_default();
            phases.verify = PhaseStatus {
                completed: true,
                items_found: findings.len(),
                duration_secs: phase_start.elapsed().as_secs(),
            };
        }

        // Phase 4: Exploit
        {
            let phase_start = std::time::Instant::now();
            let findings = self.db.get_findings_by_scan(&scan_id).unwrap_or_default();
            let sqli_findings: Vec<String> = findings.iter()
                .filter(|f| f.title.to_lowercase().contains("sql"))
                .map(|f| f.endpoint_id.as_deref().unwrap_or("").to_string())
                .collect();
            let ssrf_findings: Vec<String> = findings.iter()
                .filter(|f| f.title.to_lowercase().contains("ssrf"))
                .map(|f| f.endpoint_id.as_deref().unwrap_or("").to_string())
                .collect();

            phases.exploit = PhaseStatus {
                completed: true,
                items_found: sqli_findings.len() + ssrf_findings.len(),
                duration_secs: phase_start.elapsed().as_secs(),
            };
        }

        // Phase 5: Report
        let risk_score = {
            let phase_start = std::time::Instant::now();
            let findings = self.db.get_findings_by_scan(&scan_id).unwrap_or_default();
            let services = self.db.get_services_by_scan(&scan_id).unwrap_or_default();

            // Build attack graph and calculate risk
            let mut graph = AttackGraph::new();
            graph.build(&[], &services, &[], &findings, &[]);
            let risk = calculate_risk(&graph);

            // Generate markdown report
            let report = ScanReport {
                target: target.to_string(),
                scan_id: campaign_id.clone(),
                started_at,
                completed_at: Some(Utc::now()),
                duration_secs: Some(start.elapsed().as_secs()),
                domains: vec![],
                subdomains: vec![],
                services,
                technologies: vec![],
                endpoints: vec![],
                findings,
                exploit_refs: vec![],
            };
            let report_path = format!("reports/{}.md", campaign_id);
            MarkdownReport::write_to_file(&report, &report_path)?;
            phases.report = PhaseStatus {
                completed: true,
                items_found: 0,
                duration_secs: phase_start.elapsed().as_secs(),
            };
            risk.total_risk_score
        };

        let total_duration = start.elapsed().as_secs();
        let total_findings = phases.recon.items_found + phases.hunter.items_found
            + phases.verify.items_found + phases.exploit.items_found;

        tracing::info!("[{}] Campaign complete: {} findings in {}s", campaign_id, total_findings, total_duration);

        Ok(CampaignState {
            id: campaign_id,
            target: target.to_string(),
            started_at,
            completed_at: Some(Utc::now()),
            phases,
            findings_count: total_findings,
            risk_score,
            status: CampaignStatus::Completed,
        })
    }
}
