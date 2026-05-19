use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;
use anyhow::Result;
use std::fs;
use std::path::Path;
use std::sync::Arc;

use aegis_api::server::AppState;
use aegis_core::config::AppConfig;
use aegis_core::target::{TargetValidator, ScopeConfig};
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
        /// Scope file (JSON: {"in_scope": [...], "out_of_scope": [...]})
        #[arg(short, long)]
        scope: Option<String>,
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
    /// Continuously monitor a target for changes
    Monitor {
        /// Target domain or file containing targets
        target: String,
        /// Interval between scans in minutes
        #[arg(short, long, default_value = "60")]
        interval: u64,
        /// Output directory for historical data
        #[arg(short, long, default_value = "recon/history")]
        history_dir: String,
        #[arg(short, long, default_value = "configs/default.toml")]
        config: String,
    },
    /// Run OSINT reconnaissance against a target (crt.sh, etc.)
    Osint {
        /// Target domain
        target: String,
        #[arg(short, long, default_value = "configs/default.toml")]
        config: String,
    },
    /// Start the Aegis REST API server
    Serve {
        /// Host to bind to
        #[arg(short, long, default_value = "127.0.0.1")]
        host: String,
        /// Port to listen on
        #[arg(short, long, default_value = "4097")]
        port: u16,
        /// Config file path
        #[arg(short, long, default_value = "configs/default.toml")]
        config: String,
    },
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
            scope,
            config,
        } => {
            let config: AppConfig = load_config(&config)?;
            let mut parsed = TargetValidator::parse(&target)
                .map_err(|e| anyhow::anyhow!("{}", e))?;

            // Apply scope filtering if scope file provided
            if let Some(scope_path) = scope {
                let scope_config = ScopeConfig::load(&scope_path)
                    .map_err(|e| anyhow::anyhow!("Scope error: {}", e))?;
                println!("{}", scope_config.summary());
                // Filter targets that are out of scope
                parsed.targets = scope_config.filter(&parsed.targets);
                if parsed.targets.is_empty() {
                    anyhow::bail!("All targets are out of scope after filtering");
                }
            }

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
        Commands::Monitor { target, interval, history_dir, config } => {
            let config: AppConfig = load_config(&config)?;
            let parsed = TargetValidator::parse(&target)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            let interval_dur = std::time::Duration::from_secs(interval * 60);
            let history = if history_dir.ends_with('/') { history_dir.clone() } else { format!("{}/", history_dir) };
            fs::create_dir_all(&history)?;

            println!("[Aegis] Monitoring {} every {} minutes", parsed.normalized, interval);
            println!("[Aegis] History: {}", history);
            println!("[Aegis] Press Ctrl+C to stop\n");

            let mut iteration = 0u64;

            loop {
                iteration += 1;
                let db_path = db_path_from_config(&config);
                let db = Arc::new(Database::open(&db_path)?);
                let event_bus = EventBus::new(1024);
                let registry = PluginRegistry::new();
                let engine = SchedulerEngine::new(config.clone(), event_bus, db.clone(), registry);
                let scan_id = engine.run_scan(&parsed.normalized).await?;

                // Save current state to history dir
                let curr_file = format!("{}{}/subdomains-iter{}.txt", history, parsed.normalized, iteration);
                if let Ok(services) = db.get_services_by_scan(&scan_id) {
                    let content: String = services.iter().map(|s| format!("{}\n", s.url)).collect();
                    let dir = Path::new(&curr_file).parent().unwrap();
                    fs::create_dir_all(dir)?;
                    fs::write(&curr_file, &content)?;
                }

                // Save latest as current state
                let latest_file = format!("{}{}/subdomains.txt", history, parsed.normalized);
                if Path::new(&latest_file).exists() {
                    fs::copy(&latest_file, format!("{}{}/subdomains-prev.txt", history, parsed.normalized))?;
                }
                if Path::new(&curr_file).exists() {
                    fs::copy(&curr_file, &latest_file)?;
                }

                // Diff if we have previous state
                let prev_state = format!("{}{}/subdomains-prev.txt", history, parsed.normalized);
                if Path::new(&prev_state).exists() && Path::new(&latest_file).exists() {
                    let diff = aegis_scheduler::monitor::MonitorEngine::diff_scans(
                        &parsed.normalized, &prev_state, &latest_file,
                    )?;
                    let summary = aegis_scheduler::monitor::MonitorEngine::diff_summary(&diff);
                    if !summary.contains("No changes") {
                        println!("\n[{}] Changes detected!\n{}",
                            chrono::Utc::now().format("%Y-%m-%d %H:%M:%S"), summary);
                    } else {
                        print!(".");
                        use std::io::Write;
                        std::io::stdout().flush()?;
                    }
                }

                tokio::time::sleep(interval_dur).await;
            }
        }
        Commands::Osint { target, config } => {
            let _config: AppConfig = load_config(&config)?;
            let parsed = TargetValidator::parse(&target)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("[Aegis] Running OSINT on {}", parsed.normalized);

            // Certificate Transparency
            println!("\n── Certificate Transparency (crt.sh) ──");
            match aegis_verify::crtsh::query_crtsh(&parsed.normalized).await {
                Ok(subdomains) => {
                    for sub in &subdomains {
                        println!("  {}", sub);
                    }
                    println!("Total: {} subdomains from crt.sh", subdomains.len());
                }
                Err(e) => println!("  Error: {}", e),
            }
        }
        Commands::Serve { host, port, config } => {
            let config: AppConfig = load_config(&config)?;
            let db_path = db_path_from_config(&config);
            let db = Arc::new(
                Database::open(&db_path)
                    .map_err(|e| anyhow::anyhow!("Database error: {}", e))?,
            );
            let event_bus = EventBus::new(1024);

            let state = AppState {
                db,
                event_bus,
                config: config.clone(),
            };

            let app = aegis_api::server::create_router(state);
            let addr = format!("{}:{}", host, port);
            println!("[Aegis] API server starting on http://{}", addr);

            let listener = tokio::net::TcpListener::bind(&addr).await?;
            axum::serve(listener, app).await?;
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
