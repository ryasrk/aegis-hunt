use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;
use anyhow::Result;
use std::sync::Arc;

use aegis_core::config::AppConfig;
use aegis_core::target::TargetValidator;
use aegis_core::types::ScanReport;
use aegis_events::bus::EventBus;
use aegis_recon::registry::PluginRegistry;
use aegis_scheduler::engine::SchedulerEngine;
use aegis_storage::db::Database;
use aegis_reporting::markdown::MarkdownReport;
use aegis_reporting::json::JsonReport;

#[derive(Parser)]
#[command(name = "aegis", version, about = "Aegis Recon Intelligence Platform")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run a full scan against a target
    Scan {
        /// Target domain or file containing targets (one per line)
        target: String,
        /// Output format (markdown, json)
        #[arg(short, long, default_value = "markdown")]
        format: String,
        /// Output path for the report
        #[arg(short, long)]
        output: Option<String>,
        /// Config file path
        #[arg(short, long, default_value = "configs/default.toml")]
        config: String,
    },
    /// Run recon only (subfinder + httpx)
    Recon {
        /// Target domain
        target: String,
        #[arg(short, long, default_value = "configs/default.toml")]
        config: String,
    },
    /// List previous scans from the database
    List,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            target,
            format,
            output,
            config,
        } => {
            let config: AppConfig = load_config(&config)?;
            let parsed = TargetValidator::parse(&target)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            let db_path = db_path_from_config(&config);
            let db = Arc::new(
                Database::open(&db_path)
                    .map_err(|e| anyhow::anyhow!("Database error: {}", e))?,
            );
            let event_bus = EventBus::new(1024);
            let registry = PluginRegistry::new();
            let engine = SchedulerEngine::new(
                config.clone(),
                event_bus.clone(),
                db.clone(),
                registry,
            );

            let scan_id = engine
                .run_scan(&parsed.normalized)
                .await
                .map_err(|e| anyhow::anyhow!("{}", e))?;

            let services = db
                .get_services_by_scan(&scan_id)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            let findings = db
                .get_findings_by_scan(&scan_id)
                .map_err(|e| anyhow::anyhow!("{}", e))?;

            let report = ScanReport {
                target: parsed.normalized,
                scan_id: scan_id.clone(),
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

            let report_path =
                output.unwrap_or_else(|| format!("reports/{}.md", scan_id));
            match format.as_str() {
                "json" => JsonReport::write_to_file(&report, &report_path)
                    .map_err(|e| anyhow::anyhow!("{}", e))?,
                _ => MarkdownReport::write_to_file(&report, &report_path)?,
            }

            println!("Report written to: {}", report_path);
            println!("Scan ID: {}", scan_id);
        }
        Commands::Recon { target, config } => {
            let config: AppConfig = load_config(&config)?;
            let parsed = TargetValidator::parse(&target)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            let db_path = db_path_from_config(&config);
            let db = Arc::new(
                Database::open(&db_path)
                    .map_err(|e| anyhow::anyhow!("Database error: {}", e))?,
            );
            let event_bus = EventBus::new(1024);
            let registry = PluginRegistry::new();
            let engine = SchedulerEngine::new(config, event_bus, db.clone(), registry);

            let scan_id = engine
                .run_scan(&parsed.normalized)
                .await
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("Recon complete. Scan ID: {}", scan_id);
        }
        Commands::List => {
            println!("List: not yet implemented. Use SQLite directly on data/aegis.db");
        }
    }

    Ok(())
}

fn load_config(path: &str) -> Result<AppConfig> {
    let content = std::fs::read_to_string(path)?;
    let config: AppConfig = toml::from_str(&content)?;
    Ok(config)
}

fn db_path_from_config(config: &AppConfig) -> String {
    config
        .paths
        .data_dir
        .as_deref()
        .map(|d| format!("{}/aegis.db", d))
        .unwrap_or_else(|| "data/aegis.db".to_string())
}
