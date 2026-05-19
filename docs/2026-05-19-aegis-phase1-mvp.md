# Aegis Phase 1 MVP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the Aegis Recon Intelligence Platform Phase 1 MVP — Rust orchestrator with event bus, SQLite storage, httpx-based recon, and structured reporting.

**Architecture:** Async Rust (Tokio) workspace with 7 crates: `core` (types/config/errors), `events` (event bus), `storage` (SQLite), `scheduler` (task orchestration), `recon` (external tool plugins), `reporting` (output), and a main binary. External tools (subfinder, httpx, nuclei) are run as subprocesses via tokio::process.

**Tech Stack:** Rust, Tokio, clap, serde, rusqlite, reqwest, tracing, tera

**Location:** `/home/ryasr/personal-project/Aegis/`

---

## File Structure

```
Aegis/
├── Cargo.toml                     # Workspace root
├── crates/
│   ├── core/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── config.rs          # AppConfig, Scope, RateLimit
│   │       ├── error.rs           # AegisError enum
│   │       ├── types.rs           # Asset, Finding, Technology, Event, Target
│   │       └── target.rs          # Target validation, normalization
│   ├── events/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── bus.rs             # EventBus with typed channels
│   │       └── types.rs           # Event enum variants (27 types)
│   ├── storage/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── db.rs              # SQLite connection pool
│   │       ├── migrations.rs      # Schema setup
│   │       ├── models.rs          # Asset/Technology/Finding CRUD
│   │       └── repo.rs            # Repository pattern wrappers
│   ├── scheduler/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── engine.rs          # Main scheduler loop
│   │       ├── queue.rs           # Priority queues (Fast/Medium/Expensive/Human)
│   │       └── worker.rs          # Worker pool with bounded concurrency
│   ├── recon/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── plugin.rs          # Plugin trait
│   │       ├── subfinder.rs       # Subfinder subprocess runner
│   │       ├── httpx.rs           # Httpx subprocess runner
│   │       ├── nuclei.rs          # Nuclei subprocess runner
│   │       ├── katana.rs          # Katana subprocess runner
│   │       └── registry.rs        # Plugin registry
│   ├── intel/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── exploitdb.rs       # Exploit-db CSV parser + lookup
│   │       └── correlation.rs     # Tech → exploit matching
│   └── reporting/
│       ├── Cargo.toml
│       └── src/
│           ├── lib.rs
│           ├── markdown.rs        # Markdown report generator
│           ├── json.rs            # JSON report generator
│           └── templates.rs       # Tera template rendering
├── src/
│   └── main.rs                    # Binary: CLI entrypoint
├── data/
│   └── exploitdb/
│       └── files_exploits.csv     # Symlink or copy of exploit DB
└── configs/
    └── default.toml               # Default configuration
```

---

## Task Breakdown

### Task 1: Workspace & Core Types

**Files:**
- Create: `Cargo.toml`
- Create: `crates/core/Cargo.toml`
- Create: `crates/core/src/lib.rs`
- Create: `crates/core/src/config.rs`
- Create: `crates/core/src/error.rs`
- Create: `crates/core/src/types.rs`
- Create: `crates/core/src/target.rs`

**Details:**

The workspace Cargo.toml defines all crate members. The `core` crate defines foundational types used by every other crate.

```toml
# Cargo.toml
[workspace]
members = [
    "crates/core",
    "crates/events",
    "crates/storage",
    "crates/scheduler",
    "crates/recon",
    "crates/intel",
    "crates/reporting",
]
resolver = "2"

[workspace.dependencies]
tokio = { version = "1", features = ["full"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
clap = { version = "4", features = ["derive"] }
rusqlite = { version = "0.31", features = ["bundled"] }
thiserror = "1"
chrono = { version = "0.4", features = ["serde"] }
uuid = { version = "1", features = ["v4", "serde"] }
reqwest = { version = "0.12", features = ["json"] }
tera = "1"
anyhow = "1"
toml = "0.8"
directories = "5"
```

```rust
// crates/core/src/error.rs
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AegisError {
    #[error("Configuration error: {0}")]
    Config(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Database error: {0}")]
    Database(String),
    #[error("Plugin error: {0}")]
    Plugin(String),
    #[error("Tool execution error: {0}")]
    ToolExecution(String),
    #[error("Parse error: {0}")]
    Parse(String),
    #[error("Rate limited: retry after {0}ms")]
    RateLimited(u64),
    #[error("Scope violation: {0}")]
    ScopeViolation(String),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("Unknown error: {0}")]
    Unknown(String),
}

impl From<rusqlite::Error> for AegisError {
    fn from(e: rusqlite::Error) -> Self {
        AegisError::Database(e.to_string())
    }
}

pub type AegisResult<T> = Result<T, AegisError>;
```

```rust
// crates/core/src/types.rs
use chrono::{DateTime, Utc};
// use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Target {
    pub raw: String,
    pub normalized: String,
    pub is_file: bool,
    pub targets: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Domain {
    pub id: String,
    pub domain: String,
    pub discovered_at: DateTime<Utc>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Subdomain {
    pub id: String,
    pub domain_id: String,
    pub subdomain: String,
    pub source: String,
    pub discovered_at: DateTime<Utc>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IpAddress {
    pub id: String,
    pub subdomain_id: String,
    pub ip: String,
    pub asn: Option<String>,
    pub country: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HttpService {
    pub id: String,
    pub subdomain_id: String,
    pub url: String,
    pub status_code: u16,
    pub title: Option<String>,
    pub content_type: Option<String>,
    pub content_length: Option<u64>,
    pub server: Option<String>,
    pub tech_stack: Vec<String>,
    pub screenshot_path: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Technology {
    pub id: String,
    pub service_id: String,
    pub name: String,
    pub version: Option<String>,
    pub category: String,
    pub confidence: u8,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Endpoint {
    pub id: String,
    pub service_id: String,
    pub path: String,
    pub method: String,
    pub parameters: Vec<String>,
    pub is_api: bool,
    pub discovered_by: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Finding {
    pub id: String,
    pub service_id: Option<String>,
    pub endpoint_id: Option<String>,
    pub title: String,
    pub severity: Severity,
    pub confidence: u8,
    pub description: String,
    pub evidence: Option<String>,
    pub cve: Option<String>,
    pub edb_id: Option<u32>,
    pub remediation: Option<String>,
    pub discovered_at: DateTime<Utc>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, PartialOrd)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Critical => write!(f, "CRITICAL"),
            Severity::High => write!(f, "HIGH"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::Low => write!(f, "LOW"),
            Severity::Info => write!(f, "INFO"),
        }
    }
}

impl Severity {
    pub fn score(&self) -> u8 {
        match self {
            Severity::Critical => 100,
            Severity::High => 70,
            Severity::Medium => 40,
            Severity::Low => 20,
            Severity::Info => 5,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExploitRef {
    pub edb_id: u32,
    pub cve: Option<String>,
    pub title: String,
    pub exploit_type: String,
    pub platform: String,
    pub file_path: String,
    pub verified: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScanReport {
    pub target: String,
    pub scan_id: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub duration_secs: Option<u64>,
    pub domains: Vec<Domain>,
    pub subdomains: Vec<Subdomain>,
    pub services: Vec<HttpService>,
    pub technologies: Vec<Technology>,
    pub endpoints: Vec<Endpoint>,
    pub findings: Vec<Finding>,
    pub exploit_refs: Vec<ExploitRef>,
}
```

```rust
// crates/core/src/config.rs
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub general: GeneralConfig,
    pub rate_limits: RateLimitConfig,
    pub paths: PathConfig,
    pub plugins: PluginConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    pub max_concurrency: usize,
    pub data_dir: String,
    pub report_dir: String,
    pub db_path: String,
    pub scope_file: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    pub requests_per_second: u32,
    pub burst_size: u32,
    pub max_retries: u32,
    pub backoff_base_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathConfig {
    pub subfinder: String,
    pub httpx: String,
    pub nuclei: String,
    pub katana: String,
    pub exploitdb_csv: String,
    pub exploitdb_dir: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginConfig {
    pub enabled_plugins: Vec<String>,
    pub nuclei_severities: Vec<String>,
    pub nuclei_concurrency: usize,
    pub httpx_threads: usize,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            general: GeneralConfig {
                max_concurrency: num_cpus::get(),
                data_dir: "data".to_string(),
                report_dir: "reports".to_string(),
                db_path: "data/aegis.db".to_string(),
                scope_file: None,
            },
            rate_limits: RateLimitConfig {
                requests_per_second: 10,
                burst_size: 20,
                max_retries: 3,
                backoff_base_ms: 1000,
            },
            paths: PathConfig {
                subfinder: "subfinder".to_string(),
                httpx: "httpx".to_string(),
                nuclei: "nuclei".to_string(),
                katana: "katana".to_string(),
                exploitdb_csv: "data/exploitdb/files_exploits.csv".to_string(),
                exploitdb_dir: "data/exploitdb/".to_string(),
            },
            plugins: PluginConfig {
                enabled_plugins: vec![
                    "subfinder".into(),
                    "httpx".into(),
                    "nuclei".into(),
                    "katana".into(),
                ],
                nuclei_severities: vec![
                    "critical".into(),
                    "high".into(),
                    "medium".into(),
                ],
                nuclei_concurrency: 10,
                httpx_threads: 50,
            },
        }
    }
}
```

```rust
// crates/core/src/target.rs
use crate::error::{AegisError, AegisResult};

pub struct TargetValidator;

impl TargetValidator {
    pub fn parse(input: &str) -> AegisResult<Target> {
        let path = std::path::Path::new(input);
        if path.exists() && path.is_file() {
            let content = std::fs::read_to_string(path)?;
            let targets: Vec<String> = content
                .lines()
                .map(|l| l.trim())
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .map(|l| normalize_domain(l))
                .collect();
            if targets.is_empty() {
                return Err(AegisError::Config(
                    "Target file is empty or has no valid targets".into(),
                ));
            }
            Ok(Target {
                raw: input.to_string(),
                normalized: targets[0].clone(),
                is_file: true,
                targets,
            })
        } else {
            let normalized = normalize_domain(input);
            Ok(Target {
                raw: input.to_string(),
                normalized: normalized.clone(),
                is_file: false,
                targets: vec![normalized],
            })
        }
    }

    pub fn validate_scope(target: &str, scope_list: &[String]) -> AegisResult<()> {
        if scope_list.is_empty() {
            return Ok(());
        }
        let is_in_scope = scope_list.iter().any(|s| target.ends_with(s.trim_start_matches("*.")));
        if !is_in_scope {
            return Err(AegisError::ScopeViolation(format!(
                "{} is not in scope",
                target
            )));
        }
        Ok(())
    }
}

fn normalize_domain(input: &str) -> String {
    input
        .trim()
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .trim_end_matches('/')
        .to_lowercase()
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Target {
    pub raw: String,
    pub normalized: String,
    pub is_file: bool,
    pub targets: Vec<String>,
}
```

- [ ] **Step 1: Create workspace Cargo.toml**

```bash
cat > /home/ryasr/personal-project/Aegis/Cargo.toml << 'ENDOFFILE'
[workspace]
members = [
    "crates/core",
    "crates/events",
    "crates/storage",
    "crates/scheduler",
    "crates/recon",
    "crates/intel",
    "crates/reporting",
]
resolver = "2"

[package]
name = "aegis"
version = "0.1.0"
edition = "2021"

[dependencies]
aegis-core = { path = "crates/core" }
aegis-events = { path = "crates/events" }
aegis-storage = { path = "crates/storage" }
aegis-scheduler = { path = "crates/scheduler" }
aegis-recon = { path = "crates/recon" }
aegis-intel = { path = "crates/intel" }
aegis-reporting = { path = "crates/reporting" }
tokio = { version = "1", features = ["full"] }
clap = { version = "4", features = ["derive"] }
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
anyhow = "1"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
chrono = { version = "0.4", features = ["serde"] }
num_cpus = "1"
toml = "0.8"
directories = "5"
ENDOFFILE
```

- [ ] **Step 2: Create core crate Cargo.toml**

```bash
mkdir -p /home/ryasr/personal-project/Aegis/crates/core/src
cat > /home/ryasr/personal-project/Aegis/crates/core/Cargo.toml << 'ENDOFFILE'
[package]
name = "aegis-core"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = { version = "1", features = ["derive"] }
serde_json = "1"
chrono = { version = "0.4", features = ["serde"] }
uuid = { version = "1", features = ["v4", "serde"] }
thiserror = "1"
rusqlite = { version = "0.31", features = ["bundled"] }
num_cpus = "1"
ENDOFFILE
```

- [ ] **Step 3: Write core/src/error.rs**
- [ ] **Step 4: Write core/src/types.rs**
- [ ] **Step 5: Write core/src/config.rs**
- [ ] **Step 6: Write core/src/target.rs**
- [ ] **Step 7: Write core/src/lib.rs**
- [ ] **Step 8: Verify compilation**

```bash
cd /home/ryasr/personal-project/Aegis && cargo build -p aegis-core 2>&1
```

- [ ] **Step 9: Commit**

---

### Task 2: Event Bus

**Files:**
- Create: `crates/events/Cargo.toml`
- Create: `crates/events/src/lib.rs`
- Create: `crates/events/src/types.rs`
- Create: `crates/events/src/bus.rs`

**Details:**

Event bus with typed tokio::broadcast channels. Events flow between all engines. The bus supports subscribing to specific event types via a filter mechanism.

```rust
// crates/events/src/types.rs
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum Event {
    // Lifecycle
    ScanStarted { scan_id: String, target: String, timestamp: DateTime<Utc> },
    ScanCompleted { scan_id: String, timestamp: DateTime<Utc> },
    PhaseStarted { scan_id: String, phase: String, timestamp: DateTime<Utc> },
    PhaseCompleted { scan_id: String, phase: String, timestamp: DateTime<Utc> },

    // Recon
    SubdomainDiscovered {
        scan_id: String,
        subdomain: String,
        source: String,
        timestamp: DateTime<Utc>,
    },
    DnsResolved {
        scan_id: String,
        subdomain: String,
        ip: String,
        timestamp: DateTime<Utc>,
    },
    HttpServiceDetected {
        scan_id: String,
        url: String,
        status_code: u16,
        title: Option<String>,
        tech: Vec<String>,
        timestamp: DateTime<Utc>,
    },
    UrlDiscovered {
        scan_id: String,
        url: String,
        source: String,
        timestamp: DateTime<Utc>,
    },
    ParameterDetected {
        scan_id: String,
        url: String,
        parameter: String,
        timestamp: DateTime<Utc>,
    },
    TechnologyDetected {
        scan_id: String,
        url: String,
        technology: String,
        version: Option<String>,
        timestamp: DateTime<Utc>,
    },
    JsAssetDiscovered {
        scan_id: String,
        url: String,
        asset_url: String,
        timestamp: DateTime<Utc>,
    },
    ApiEndpointDiscovered {
        scan_id: String,
        url: String,
        method: String,
        timestamp: DateTime<Utc>,
    },
    SecretDetected {
        scan_id: String,
        url: String,
        secret_type: String,
        context: String,
        timestamp: DateTime<Utc>,
    },

    // Intel
    ExploitCorrelated {
        scan_id: String,
        technology: String,
        edb_id: u32,
        cve: Option<String>,
        timestamp: DateTime<Utc>,
    },

    // Findings
    CandidateFinding {
        scan_id: String,
        finding_id: String,
        title: String,
        severity: String,
        timestamp: DateTime<Utc>,
    },
    VerifiedFinding {
        scan_id: String,
        finding_id: String,
        confidence: u8,
        timestamp: DateTime<Utc>,
    },
    AttackPathGenerated {
        scan_id: String,
        path: Vec<String>,
        timestamp: DateTime<Utc>,
    },

    // Error
    Error { scan_id: String, message: String, timestamp: DateTime<Utc> },
    RateLimited { scan_id: String, host: String, retry_ms: u64, timestamp: DateTime<Utc> },
}

impl Event {
    pub fn scan_id(&self) -> Option<&str> {
        match self {
            Event::ScanStarted { scan_id, .. } => Some(scan_id),
            Event::ScanCompleted { scan_id, .. } => Some(scan_id),
            Event::PhaseStarted { scan_id, .. } => Some(scan_id),
            Event::PhaseCompleted { scan_id, .. } => Some(scan_id),
            Event::SubdomainDiscovered { scan_id, .. } => Some(scan_id),
            Event::DnsResolved { scan_id, .. } => Some(scan_id),
            Event::HttpServiceDetected { scan_id, .. } => Some(scan_id),
            Event::UrlDiscovered { scan_id, .. } => Some(scan_id),
            Event::ParameterDetected { scan_id, .. } => Some(scan_id),
            Event::TechnologyDetected { scan_id, .. } => Some(scan_id),
            Event::JsAssetDiscovered { scan_id, .. } => Some(scan_id),
            Event::ApiEndpointDiscovered { scan_id, .. } => Some(scan_id),
            Event::SecretDetected { scan_id, .. } => Some(scan_id),
            Event::ExploitCorrelated { scan_id, .. } => Some(scan_id),
            Event::CandidateFinding { scan_id, .. } => Some(scan_id),
            Event::VerifiedFinding { scan_id, .. } => Some(scan_id),
            Event::AttackPathGenerated { scan_id, .. } => Some(scan_id),
            Event::Error { scan_id, .. } => Some(scan_id),
            Event::RateLimited { scan_id, .. } => Some(scan_id),
        }
    }
}

pub enum EventKind {
    Lifecycle,
    Recon,
    Intel,
    Finding,
    Error,
}

impl Event {
    pub fn kind(&self) -> EventKind {
        match self {
            Event::ScanStarted { .. } | Event::ScanCompleted { .. }
            | Event::PhaseStarted { .. } | Event::PhaseCompleted { .. } => EventKind::Lifecycle,
            Event::SubdomainDiscovered { .. } | Event::DnsResolved { .. }
            | Event::HttpServiceDetected { .. } | Event::UrlDiscovered { .. }
            | Event::ParameterDetected { .. } | Event::TechnologyDetected { .. }
            | Event::JsAssetDiscovered { .. } | Event::ApiEndpointDiscovered { .. }
            | Event::SecretDetected { .. } => EventKind::Recon,
            Event::ExploitCorrelated { .. } => EventKind::Intel,
            Event::CandidateFinding { .. } | Event::VerifiedFinding { .. }
            | Event::AttackPathGenerated { .. } => EventKind::Finding,
            Event::Error { .. } | Event::RateLimited { .. } => EventKind::Error,
        }
    }
}
```

```rust
// crates/events/src/bus.rs
use tokio::sync::broadcast;
use crate::types::Event;

#[derive(Debug, Clone)]
pub struct EventBus {
    tx: broadcast::Sender<Event>,
}

impl EventBus {
    pub fn new(capacity: usize) -> Self {
        let (tx, _) = broadcast::channel(capacity);
        Self { tx }
    }

    pub fn emit(&self, event: Event) -> Result<usize, broadcast::error::SendError<Event>> {
        let count = self.tx.send(event)?;
        Ok(count)
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.tx.subscribe()
    }

    pub fn subscriber_count(&self) -> usize {
        self.tx.receiver_count()
    }
}
```

- [ ] **Step 1: Create events crate files**
- [ ] **Step 2: Verify compilation**

```bash
cd /home/ryasr/personal-project/Aegis && cargo build -p aegis-events 2>&1
```

- [ ] **Step 3: Commit**

---

### Task 3: SQLite Storage

**Files:**
- Create: `crates/storage/Cargo.toml`
- Create: `crates/storage/src/lib.rs`
- Create: `crates/storage/src/db.rs`
- Create: `crates/storage/src/migrations.rs`
- Create: `crates/storage/src/models.rs`

- [ ] **Step 1: Create storage Cargo.toml**

```toml
# crates/storage/Cargo.toml
[package]
name = "aegis-storage"
version = "0.1.0"
edition = "2021"

[dependencies]
aegis-core = { path = "../core" }
rusqlite = { version = "0.31", features = ["bundled"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
chrono = { version = "0.4", features = ["serde"] }
uuid = { version = "1", features = ["v4"] }
tracing = "0.1"
```

- [ ] **Step 2: Write migrations.rs**

```rust
// crates/storage/src/migrations.rs
use rusqlite::Connection;
use tracing::info;

pub fn run_migrations(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch("PRAGMA journal_mode=WAL;")?;
    conn.execute_batch("PRAGMA foreign_keys=ON;")?;

    conn.execute_batch("
        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            target TEXT NOT NULL,
            started_at TEXT NOT NULL,
            completed_at TEXT,
            status TEXT NOT NULL DEFAULT 'running'
        );

        CREATE TABLE IF NOT EXISTS domains (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            domain TEXT NOT NULL,
            discovered_at TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        );

        CREATE TABLE IF NOT EXISTS subdomains (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            domain_id TEXT NOT NULL,
            subdomain TEXT NOT NULL,
            source TEXT NOT NULL,
            resolved_ip TEXT,
            discovered_at TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES scans(id),
            FOREIGN KEY (domain_id) REFERENCES domains(id)
        );

        CREATE TABLE IF NOT EXISTS services (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            subdomain_id TEXT NOT NULL,
            url TEXT NOT NULL,
            status_code INTEGER,
            title TEXT,
            content_type TEXT,
            content_length INTEGER,
            server TEXT,
            tech_json TEXT,
            screenshot_path TEXT,
            discovered_at TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES scans(id),
            FOREIGN KEY (subdomain_id) REFERENCES subdomains(id)
        );

        CREATE TABLE IF NOT EXISTS technologies (
            id TEXT PRIMARY KEY,
            service_id TEXT NOT NULL,
            name TEXT NOT NULL,
            version TEXT,
            category TEXT,
            confidence INTEGER DEFAULT 100,
            FOREIGN KEY (service_id) REFERENCES services(id)
        );

        CREATE TABLE IF NOT EXISTS endpoints (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            service_id TEXT NOT NULL,
            path TEXT NOT NULL,
            method TEXT DEFAULT 'GET',
            parameters TEXT,
            is_api INTEGER DEFAULT 0,
            discovered_by TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id),
            FOREIGN KEY (service_id) REFERENCES services(id)
        );

        CREATE TABLE IF NOT EXISTS findings (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            service_id TEXT,
            endpoint_id TEXT,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            confidence INTEGER DEFAULT 50,
            description TEXT,
            evidence TEXT,
            cve TEXT,
            edb_id INTEGER,
            remediation TEXT,
            discovered_at TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        );

        CREATE TABLE IF NOT EXISTS exploit_refs (
            id TEXT PRIMARY KEY,
            finding_id TEXT,
            edb_id INTEGER NOT NULL,
            cve TEXT,
            exploit_title TEXT NOT NULL,
            exploit_type TEXT,
            platform TEXT,
            file_path TEXT,
            verified INTEGER DEFAULT 0,
            FOREIGN KEY (finding_id) REFERENCES findings(id)
        );

        CREATE INDEX IF NOT EXISTS idx_subdomains_scan ON subdomains(scan_id);
        CREATE INDEX IF NOT EXISTS idx_services_scan ON services(scan_id);
        CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
        CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
        CREATE INDEX IF NOT EXISTS idx_technologies_name ON technologies(name);
    ")?;

    info!("Database schema initialized");
    Ok(())
}
```

- [ ] **Step 3: Write db.rs**

```rust
// crates/storage/src/db.rs
use rusqlite::Connection;
use std::sync::Mutex;
use tracing::info;
use crate::migrations;

pub struct Database {
    conn: Mutex<Connection>,
}

impl Database {
    pub fn open(path: &str) -> rusqlite::Result<Self> {
        let conn = Connection::open(path)?;
        let db = Self { conn: Mutex::new(conn) };
        {
            let conn = db.conn.lock().unwrap();
            migrations::run_migrations(&conn)?;
        }
        info!("Database opened: {}", path);
        Ok(db)
    }

    pub fn open_in_memory() -> rusqlite::Result<Self> {
        let conn = Connection::open_in_memory()?;
        let db = Self { conn: Mutex::new(conn) };
        {
            let conn = db.conn.lock().unwrap();
            migrations::run_migrations(&conn)?;
        }
        Ok(db)
    }

    pub fn conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap()
    }
}
```

- [ ] **Step 4: Write models.rs (CRUD operations)**

```rust
// crates/storage/src/models.rs
use aegis_core::types::*;
use crate::Database;
use chrono::Utc;
use uuid::Uuid;
use tracing::debug;

impl Database {
    pub fn create_scan(&self, target: &str) -> rusqlite::Result<String> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();
        let conn = self.conn();
        conn.execute(
            "INSERT INTO scans (id, target, started_at, status) VALUES (?1, ?2, ?3, 'running')",
            rusqlite::params![id, target, now],
        )?;
        debug!("Created scan: {} for target: {}", id, target);
        Ok(id)
    }

    pub fn complete_scan(&self, scan_id: &str) -> rusqlite::Result<()> {
        let now = Utc::now().to_rfc3339();
        let conn = self.conn();
        conn.execute(
            "UPDATE scans SET completed_at = ?1, status = 'completed' WHERE id = ?2",
            rusqlite::params![now, scan_id],
        )?;
        Ok(())
    }

    pub fn insert_subdomain(
        &self,
        scan_id: &str,
        domain_id: &str,
        subdomain: &str,
        source: &str,
    ) -> rusqlite::Result<String> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();
        let conn = self.conn();
        conn.execute(
            "INSERT INTO subdomains (id, scan_id, domain_id, subdomain, source, discovered_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![id, scan_id, domain_id, subdomain, source, now],
        )?;
        Ok(id)
    }

    pub fn insert_service(
        &self,
        scan_id: &str,
        subdomain_id: &str,
        url: &str,
        status_code: u16,
        title: Option<&str>,
        tech: &[String],
    ) -> rusqlite::Result<String> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();
        let tech_json = serde_json::to_string(tech).unwrap_or_default();
        let conn = self.conn();
        conn.execute(
            "INSERT INTO services (id, scan_id, subdomain_id, url, status_code, title, tech_json, discovered_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![id, scan_id, subdomain_id, url, status_code, title, tech_json, now],
        )?;
        Ok(id)
    }

    pub fn insert_finding(
        &self,
        scan_id: &str,
        service_id: Option<&str>,
        title: &str,
        severity: &str,
        confidence: u8,
        description: &str,
        cve: Option<&str>,
        remediation: Option<&str>,
    ) -> rusqlite::Result<String> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();
        let conn = self.conn();
        conn.execute(
            "INSERT INTO findings (id, scan_id, service_id, title, severity, confidence, description, cve, remediation, discovered_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            rusqlite::params![id, scan_id, service_id, title, severity, confidence, description, cve, remediation, now],
        )?;
        Ok(id)
    }

    pub fn get_findings_by_scan(&self, scan_id: &str) -> rusqlite::Result<Vec<Finding>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT id, service_id, endpoint_id, title, severity, confidence, description, evidence, cve, edb_id, remediation, discovered_at
             FROM findings WHERE scan_id = ?1 ORDER BY
             CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END",
        )?;
        let rows = stmt.query_map(rusqlite::params![scan_id], |row| {
            Ok(Finding {
                id: row.get(0)?,
                service_id: row.get(1)?,
                endpoint_id: row.get(2)?,
                title: row.get(3)?,
                severity: row.get::<_, String>(4)?.parse().unwrap_or(Severity::Info),
                confidence: row.get::<_, u8>(5)?,
                description: row.get(6)?,
                evidence: row.get(7)?,
                cve: row.get(8)?,
                edb_id: row.get(9)?,
                remediation: row.get(10)?,
                discovered_at: row.get::<_, String>(11)?.parse().unwrap_or_else(|_| Utc::now()),
            })
        })?;
        rows.collect()
    }

    pub fn get_services_by_scan(&self, scan_id: &str) -> rusqlite::Result<Vec<HttpService>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT id, subdomain_id, url, status_code, title, content_type, content_length, server, tech_json, screenshot_path, discovered_at
             FROM services WHERE scan_id = ?1",
        )?;
        let rows = stmt.query_map(rusqlite::params![scan_id], |row| {
            let tech_json: Option<String> = row.get(8)?;
            let tech: Vec<String> = tech_json
                .and_then(|j| serde_json::from_str(&j).ok())
                .unwrap_or_default();
            Ok(HttpService {
                id: row.get(0)?,
                subdomain_id: row.get(1)?,
                url: row.get(2)?,
                status_code: row.get(3)?,
                title: row.get(4)?,
                content_type: row.get(5)?,
                content_length: row.get(6)?,
                server: row.get(7)?,
                tech_stack: tech,
                screenshot_path: row.get(9)?,
            })
        })?;
        rows.collect()
    }
}
```

- [ ] **Step 5: Verify compilation**

```bash
cd /home/ryasr/personal-project/Aegis && cargo build -p aegis-storage 2>&1
```

- [ ] **Step 6: Commit**

---

### Task 4: Recon Plugin System + Subfinder Integration

**Files:**
- Create: `crates/recon/Cargo.toml`
- Create: `crates/recon/src/lib.rs`
- Create: `crates/recon/src/plugin.rs`
- Create: `crates/recon/src/subfinder.rs`
- Create: `crates/recon/src/httpx.rs`
- Create: `crates/recon/src/registry.rs`

- [ ] **Step 1: Create recon Cargo.toml**

```toml
[package]
name = "aegis-recon"
version = "0.1.0"
edition = "2021"

[dependencies]
aegis-core = { path = "../core" }
aegis-events = { path = "../events" }
tokio = { version = "1", features = ["full"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
tracing = "0.1"
anyhow = "1"
chrono = { version = "0.4", features = ["serde"] }
uuid = { version = "1", features = ["v4"] }
```

- [ ] **Step 2: Write plugin trait**

```rust
// crates/recon/src/plugin.rs
use aegis_core::error::AegisResult;
use async_trait::async_trait;

#[async_trait]
pub trait ReconPlugin: Send + Sync {
    fn name(&self) -> &'static str;
    async fn execute(&self, target: &str, scan_id: &str) -> AegisResult<Vec<String>>;
}

// We avoid async_trait dep by using Box<dyn Future> or just making it simple
// For MVP: simplify to sync trait with tokio::task::spawn_blocking for tools
pub trait ReconPluginSync: Send + Sync {
    fn name(&self) -> &'static str;
    fn execute(&self, target: &str, scan_id: &str) -> AegisResult<Vec<String>>;
}
```

```rust
// crates/recon/src/subfinder.rs
use crate::plugin::ReconPluginSync;
use aegis_core::error::{AegisError, AegisResult};
use std::process::Command;
use tracing::{info, error};

pub struct SubfinderPlugin;

impl ReconPluginSync for SubfinderPlugin {
    fn name(&self) -> &'static str {
        "subfinder"
    }

    fn execute(&self, target: &str, scan_id: &str) -> AegisResult<Vec<String>> {
        info!("[{}] Running subfinder on {}", scan_id, target);

        let output = Command::new("subfinder")
            .arg("-d")
            .arg(target)
            .arg("-silent")
            .arg("-all")
            .output()
            .map_err(|e| AegisError::ToolExecution(format!("subfinder failed: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            error!("[{}] subfinder error: {}", scan_id, stderr);
            return Err(AegisError::ToolExecution(format!(
                "subfinder exited with {}: {}",
                output.status, stderr
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let domains: Vec<String> = stdout
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect();

        info!("[{}] subfinder found {} subdomains", scan_id, domains.len());
        Ok(domains)
    }
}
```

```rust
// crates/recon/src/httpx.rs
use crate::plugin::ReconPluginSync;
use aegis_core::error::{AegisError, AegisResult};
use std::process::Command;
use tracing::{info, error};

pub struct HttpxPlugin;

impl ReconPluginSync for HttpxPlugin {
    fn name(&self) -> &'static str {
        "httpx"
    }

    fn execute(&self, target: &str, _scan_id: &str) -> AegisResult<Vec<String>> {
        info!("Running httpx on {}", target);

        let output = Command::new("httpx")
            .arg("-u")
            .arg(target)
            .arg("-silent")
            .arg("-status-code")
            .arg("-title")
            .arg("-tech-detect")
            .arg("-content-length")
            .arg("-json")
            .output()
            .map_err(|e| AegisError::ToolExecution(format!("httpx failed: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(AegisError::ToolExecution(format!(
                "httpx exited with {}: {}",
                output.status, stderr
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let results: Vec<String> = stdout.lines().map(|l| l.to_string()).collect();
        info!("httpx returned {} results", results.len());
        Ok(results)
    }
}
```

```rust
// crates/recon/src/registry.rs
use crate::plugin::ReconPluginSync;
use crate::subfinder::SubfinderPlugin;
use crate::httpx::HttpxPlugin;
use aegis_core::error::AegisResult;

pub struct PluginRegistry {
    plugins: Vec<Box<dyn ReconPluginSync>>,
}

impl PluginRegistry {
    pub fn new() -> Self {
        let plugins: Vec<Box<dyn ReconPluginSync>> = vec![
            Box::new(SubfinderPlugin),
            Box::new(HttpxPlugin),
        ];
        Self { plugins }
    }

    pub fn get(&self, name: &str) -> Option<&dyn ReconPluginSync> {
        self.plugins.iter().find(|p| p.name() == name).map(|p| p.as_ref())
    }

    pub fn all(&self) -> &[Box<dyn ReconPluginSync>] {
        &self.plugins
    }

    pub fn execute_all(&self, target: &str, scan_id: &str) -> AegisResult<()> {
        for plugin in &self.plugins {
            let result = plugin.execute(target, scan_id)?;
            tracing::info!("[{}] {} produced {} results", scan_id, plugin.name(), result.len());
        }
        Ok(())
    }

    pub fn execute_named(&self, names: &[String], target: &str, scan_id: &str) -> AegisResult<()> {
        for name in names {
            if let Some(plugin) = self.get(name) {
                let result = plugin.execute(target, scan_id)?;
                tracing::info!("[{}] {} produced {} results", scan_id, name, result.len());
            } else {
                tracing::warn!("[{}] Plugin '{}' not found", scan_id, name);
            }
        }
        Ok(())
    }
}
```

- [ ] **Step 3: Write recon/src/lib.rs**

```rust
pub mod plugin;
pub mod subfinder;
pub mod httpx;
pub mod registry;
```

- [ ] **Step 4: Create crates/recon/Cargo.toml**
- [ ] **Step 5: Verify compilation**

```bash
cd /home/ryasr/personal-project/Aegis && cargo build -p aegis-recon 2>&1
```

- [ ] **Step 6: Commit**

---

### Task 5: Intel Engine — Exploit-DB Integration

**Files:**
- Create: `crates/intel/Cargo.toml`
- Create: `crates/intel/src/lib.rs`
- Create: `crates/intel/src/exploitdb.rs`
- Create: `crates/intel/src/correlation.rs`

- [ ] **Step 1: Create intel Cargo.toml**

```toml
[package]
name = "aegis-intel"
version = "0.1.0"
edition = "2021"

[dependencies]
aegis-core = { path = "../core" }
aegis-events = { path = "../events" }
serde = { version = "1", features = ["derive"] }
csv = "1.3"
tracing = "0.1"
aho-corasick = "1"
```

- [ ] **Step 2: Write exploitdb.rs**

```rust
// crates/intel/src/exploitdb.rs
use aegis_core::types::ExploitRef;
use aegis_core::error::{AegisError, AegisResult};
use std::collections::HashMap;
use std::path::Path;

pub struct ExploitDbIndex {
    exploits: Vec<ExploitRef>,
    tech_index: HashMap<String, Vec<usize>>,  // lowercase tech → indices
    cve_index: HashMap<String, Vec<usize>>,   // CVE ID → indices
}

impl ExploitDbIndex {
    pub fn new() -> Self {
        Self {
            exploits: Vec::new(),
            tech_index: HashMap::new(),
            cve_index: HashMap::new(),
        }
    }

    pub fn load_csv(path: &str) -> AegisResult<Self> {
        if !Path::new(path).exists() {
            tracing::warn!("ExploitDB CSV not found at: {}", path);
            return Ok(Self::new());
        }

        let mut rdr = csv::ReaderBuilder::new()
            .has_headers(true)
            .flexible(true)
            .from_path(path)
            .map_err(|e| AegisError::Parse(format!("Failed to read CSV: {}", e)))?;

        let mut exploits = Vec::new();
        let mut tech_index: HashMap<String, Vec<usize>> = HashMap::new();
        let mut cve_index: HashMap<String, Vec<usize>> = HashMap::new();

        for (idx, result) in rdr.records().enumerate() {
            if let Ok(record) = result {
                let edb_id: u32 = record.get(0).unwrap_or("0").parse().unwrap_or(0);
                let file = record.get(1).unwrap_or("").to_string();
                let description = record.get(2).unwrap_or("").to_string();
                let exploit_type = record.get(5).unwrap_or("").to_string();
                let platform = record.get(6).unwrap_or("").to_string();
                let codes = record.get(11).unwrap_or("").to_string();
                let verified: bool = record.get(10).unwrap_or("0").parse::<u8>().unwrap_or(0) == 1;

                // Parse CVEs from codes column
                let cves: Vec<String> = codes
                    .split(';')
                    .filter(|c| c.starts_with("CVE-"))
                    .map(|c| c.trim().to_string())
                    .collect();

                let exploit = ExploitRef {
                    edb_id,
                    cve: cves.first().cloned(),
                    title: description,
                    exploit_type: exploit_type.clone(),
                    platform: platform.clone(),
                    file_path: file,
                    verified,
                };

                // Index by technology (words in description, platform, type)
                let keywords: Vec<String> = description
                    .to_lowercase()
                    .split(|c: char| !c.is_alphanumeric())
                    .filter(|w| w.len() > 3)
                    .map(|w| w.to_string())
                    .collect();

                for kw in keywords {
                    tech_index.entry(kw).or_default().push(idx);
                }

                // Index by CVE
                for cve in &cves {
                    cve_index.entry(cve.clone()).or_default().push(idx);
                }

                // Also index platform + type
                if !platform.is_empty() {
                    tech_index
                        .entry(platform.to_lowercase())
                        .or_default()
                        .push(idx);
                }

                exploits.push(exploit);
            }
        }

        tracing::info!(
            "Loaded {} exploits from CSV ({} tech entries, {} CVE entries)",
            exploits.len(),
            tech_index.len(),
            cve_index.len()
        );

        Ok(Self {
            exploits,
            tech_index,
            cve_index,
        })
    }

    pub fn search_by_tech(&self, technology: &str) -> Vec<&ExploitRef> {
        let lower = technology.to_lowercase();
        let mut seen = std::collections::HashSet::new();
        let mut results = Vec::new();

        // Split into keywords
        let keywords: Vec<&str> = lower.split(|c: char| !c.is_alphanumeric())
            .filter(|w| w.len() > 2)
            .collect();

        for kw in keywords {
            if let Some(indices) = self.tech_index.get(kw) {
                for &idx in indices {
                    if seen.insert(idx) {
                        results.push(&self.exploits[idx]);
                    }
                }
            }
        }

        results.sort_by(|a, b| b.verified as u8.cmp(&a.verified as u8));
        results.truncate(20);
        results
    }

    pub fn search_by_cve(&self, cve: &str) -> Option<&ExploitRef> {
        let upper = cve.to_uppercase();
        self.cve_index.get(&upper).and_then(|indices| {
            indices.first().map(|&idx| &self.exploits[idx])
        })
    }

    pub fn search_by_platform(&self, platform: &str, exploit_type: &str) -> Vec<&ExploitRef> {
        self.exploits
            .iter()
            .filter(|e| {
                e.platform.to_lowercase() == platform.to_lowercase()
                    && e.exploit_type.to_lowercase() == exploit_type.to_lowercase()
            })
            .take(20)
            .collect()
    }

    pub fn total_count(&self) -> usize {
        self.exploits.len()
    }
}
```

- [ ] **Step 3: Write correlation.rs**

```rust
// crates/intel/src/correlation.rs
use crate::exploitdb::ExploitDbIndex;
use aegis_core::types::ExploitRef;

pub struct CorrelationEngine {
    exploit_db: ExploitDbIndex,
}

impl CorrelationEngine {
    pub fn new(exploit_db: ExploitDbIndex) -> Self {
        Self { exploit_db }
    }

    /// Given a list of detected technologies, return all matching exploits
    pub fn correlate_technologies(&self, technologies: &[String]) -> Vec<CorrelatedExploit> {
        let mut results = Vec::new();
        let mut seen = std::collections::HashSet::new();

        for tech in technologies {
            let matches = self.exploit_db.search_by_tech(tech);
            for exploit in matches {
                if seen.insert(exploit.edb_id) {
                    results.push(CorrelatedExploit {
                        trigger_technology: tech.clone(),
                        exploit: exploit.clone(),
                    });
                }
            }
        }

        results
    }

    /// Given a CVE ID, find the exploit details
    pub fn correlate_cve(&self, cve: &str) -> Option<&ExploitRef> {
        self.exploit_db.search_by_cve(cve)
    }

    pub fn exploit_db(&self) -> &ExploitDbIndex {
        &self.exploit_db
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CorrelatedExploit {
    pub trigger_technology: String,
    pub exploit: ExploitRef,
}
```

- [ ] **Step 4: Create intel/src/lib.rs**
- [ ] **Step 5: Verify compilation**

```bash
cd /home/ryasr/personal-project/Aegis && cargo build -p aegis-intel 2>&1
```

- [ ] **Step 6: Commit**

---

### Task 6: Scheduler Engine

**Files:**
- Create: `crates/scheduler/Cargo.toml`
- Create: `crates/scheduler/src/lib.rs`
- Create: `crates/scheduler/src/engine.rs`
- Create: `crates/scheduler/src/queue.rs`
- Create: `crates/scheduler/src/worker.rs`

- [ ] **Step 1: Write queue.rs**

```rust
// crates/scheduler/src/queue.rs
use aegis_core::error::AegisResult;
use std::sync::mpsc;
use tracing::debug;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum QueuePriority {
    Fast,     // DNS, HEAD requests, favicon hashing
    Medium,   // Crawling, JS analysis, endpoint extraction
    Expensive, // Deep nuclei, authenticated workflows
    Human,    // Manual validation, exploit review
}

#[derive(Debug, Clone)]
pub struct QueueItem {
    pub id: String,
    pub task_type: String,
    pub target: String,
    pub payload: String,
    pub priority: QueuePriority,
    pub score: u32,
}

pub struct PriorityQueue {
    fast_tx: mpsc::Sender<QueueItem>,
    fast_rx: mpsc::Receiver<QueueItem>,
    medium_tx: mpsc::Sender<QueueItem>,
    medium_rx: mpsc::Receiver<QueueItem>,
    expensive_tx: mpsc::Sender<QueueItem>,
    expensive_rx: mpsc::Receiver<QueueItem>,
    human_tx: mpsc::Sender<QueueItem>,
    human_rx: mpsc::Receiver<QueueItem>,
}

impl PriorityQueue {
    pub fn new() -> Self {
        let (fast_tx, fast_rx) = mpsc::channel();
        let (medium_tx, medium_rx) = mpsc::channel();
        let (expensive_tx, expensive_rx) = mpsc::channel();
        let (human_tx, human_rx) = mpsc::channel();
        Self {
            fast_tx, fast_rx,
            medium_tx, medium_rx,
            expensive_tx, expensive_rx,
            human_tx, human_rx,
        }
    }

    pub fn enqueue(&self, item: QueueItem) -> AegisResult<()> {
        debug!("Enqueuing {} task: {}", item.task_type, item.target);
        match item.priority {
            QueuePriority::Fast => self.fast_tx.send(item).ok(),
            QueuePriority::Medium => self.medium_tx.send(item).ok(),
            QueuePriority::Expensive => self.expensive_tx.send(item).ok(),
            QueuePriority::Human => self.human_tx.send(item).ok(),
        };
        Ok(())
    }

    pub fn dequeue_fast(&self) -> Option<QueueItem> {
        self.fast_rx.try_recv().ok()
    }

    pub fn dequeue_medium(&self) -> Option<QueueItem> {
        self.medium_rx.try_recv().ok()
    }

    pub fn dequeue_expensive(&self) -> Option<QueueItem> {
        self.expensive_rx.try_recv().ok()
    }

    pub fn dequeue_human(&self) -> Option<QueueItem> {
        self.human_rx.try_recv().ok()
    }

    pub fn dequeue(&self) -> Option<QueueItem> {
        // Priority order: try fast first, then medium, then expensive
        self.dequeue_fast()
            .or_else(|| self.dequeue_medium())
            .or_else(|| self.dequeue_expensive())
    }
}
```

```rust
// crates/scheduler/src/engine.rs
use crate::queue::PriorityQueue;
use aegis_core::config::AppConfig;
use aegis_core::error::AegisResult;
use aegis_events::bus::EventBus;
use aegis_events::types::Event;
use aegis_recon::registry::PluginRegistry;
use aegis_storage::Database;
use chrono::Utc;
use tracing::{info, error};

pub struct SchedulerEngine {
    config: AppConfig,
    event_bus: EventBus,
    db: std::sync::Arc<Database>,
    registry: PluginRegistry,
    queue: PriorityQueue,
}

impl SchedulerEngine {
    pub fn new(
        config: AppConfig,
        event_bus: EventBus,
        db: std::sync::Arc<Database>,
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

    pub async fn run_scan(&self, target: &str) -> AegisResult<String> {
        let scan_id = self.db.create_scan(target)?;
        let now = Utc::now();

        self.event_bus.emit(Event::ScanStarted {
            scan_id: scan_id.clone(),
            target: target.to_string(),
            timestamp: now,
        }).ok();

        info!("[{}] Starting scan on target: {}", scan_id, target);

        // Phase 1: Passive Recon
        self.event_bus.emit(Event::PhaseStarted {
            scan_id: scan_id.clone(),
            phase: "recon".into(),
            timestamp: Utc::now(),
        }).ok();

        // Run subfinder
        if let Some(plugin) = self.registry.get("subfinder") {
            match plugin.execute(target, &scan_id) {
                Ok(subdomains) => {
                    for sub in &subdomains {
                        self.event_bus.emit(Event::SubdomainDiscovered {
                            scan_id: scan_id.clone(),
                            subdomain: sub.clone(),
                            source: "subfinder".into(),
                            timestamp: Utc::now(),
                        }).ok();
                    }
                    info!("[{}] Found {} subdomains", scan_id, subdomains.len());
                }
                Err(e) => {
                    error!("[{}] Subfinder error: {}", scan_id, e);
                }
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

    pub fn event_bus(&self) -> &EventBus {
        &self.event_bus
    }

    pub fn db(&self) -> &Database {
        &self.db
    }
}
```

- [ ] **Step 2: Create scheduler Cargo.toml**
- [ ] **Step 3: Write all scheduler source files**
- [ ] **Step 4: Verify compilation**

```bash
cd /home/ryasr/personal-project/Aegis && cargo build -p aegis-scheduler 2>&1
```

- [ ] **Step 5: Commit**

---

### Task 7: Reporting Engine

**Files:**
- Create: `crates/reporting/Cargo.toml`
- Create: `crates/reporting/src/lib.rs`
- Create: `crates/reporting/src/markdown.rs`
- Create: `crates/reporting/src/json.rs`

- [ ] **Step 1: Create reporting Cargo.toml**

```toml
[package]
name = "aegis-reporting"
version = "0.1.0"
edition = "2021"

[dependencies]
aegis-core = { path = "../core" }
aegis-storage = { path = "../storage" }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
chrono = { version = "0.4", features = ["serde"] }
tracing = "0.1"
```

- [ ] **Step 2: Write markdown.rs**

```rust
// crates/reporting/src/markdown.rs
use aegis_core::types::{Finding, Severity, ScanReport, ExploitRef, HttpService};
use chrono::Utc;
use std::path::Path;
use std::fs;

pub struct MarkdownReport;

impl MarkdownReport {
    pub fn generate(report: &ScanReport) -> String {
        let mut output = String::new();

        // Header
        output.push_str(&format!("# Aegis Scan Report\n\n"));
        output.push_str(&format!("**Target:** `{}`\n", report.target));
        output.push_str(&format!("**Scan ID:** `{}`\n", report.scan_id));
        if let Some(duration) = report.duration_secs {
            output.push_str(&format!("**Duration:** {} seconds\n", duration));
        }
        output.push_str(&format!("**Date:** {}\n\n", Utc::now().format("%Y-%m-%d %H:%M:%S UTC")));

        // Summary
        output.push_str("## Summary\n\n");
        let critical = report.findings.iter().filter(|f| f.severity == Severity::Critical).count();
        let high = report.findings.iter().filter(|f| f.severity == Severity::High).count();
        let medium = report.findings.iter().filter(|f| f.severity == Severity::Medium).count();
        let low = report.findings.iter().filter(|f| f.severity == Severity::Low).count();

        output.push_str(&format!(
            "| Severity | Count |\n|----------|-------|\n\
             | Critical | {} |\n| High     | {} |\n| Medium   | {} |\n| Low      | {} |\n\n",
            critical, high, medium, low
        ));

        output.push_str(&format!("**Total Findings:** {}\n\n", report.findings.len()));
        output.push_str(&format!("**Subdomains Discovered:** {}\n\n", report.subdomains.len()));
        output.push_str(&format!("**Live Services:** {}\n\n", report.services.len()));
        output.push_str(&format!("**Technologies Detected:** {}\n\n", report.technologies.len()));

        // Surface
        output.push_str("## Attack Surface\n\n");
        output.push_str("| URL | Status | Title | Tech |\n|-----|--------|-------|------|\n");
        for service in &report.services {
            let tech_str = service.tech_stack.join(", ");
            let title = service.title.as_deref().unwrap_or("-");
            output.push_str(&format!(
                "| {} | {} | {} | {} |\n",
                service.url, service.status_code, title, tech_str
            ));
        }
        output.push_str("\n");

        // Findings
        if !report.findings.is_empty() {
            output.push_str("## Findings\n\n");
            for finding in &report.findings {
                output.push_str(&format!("### {}: {}\n\n", finding.severity, finding.title));
                output.push_str(&format!("**Confidence:** {}%\n\n", finding.confidence));
                output.push_str(&format!("**Description:** {}\n\n", finding.description));

                if let Some(ref evidence) = finding.evidence {
                    output.push_str("**Evidence:**\n```\n");
                    output.push_str(evidence);
                    output.push_str("\n```\n\n");
                }

                if let Some(ref cve) = finding.cve {
                    output.push_str(&format!("**CVE:** `{}`\n\n", cve));
                }
                if let Some(ref remediation) = finding.remediation {
                    output.push_str(&format!("**Remediation:** {}\n\n", remediation));
                }
            }
        }

        // Exploit References
        if !report.exploit_refs.is_empty() {
            output.push_str("## Exploit References\n\n");
            output.push_str("| EDB ID | CVE | Title | Type | Path |\n|--------|-----|-------|------|------|\n");
            for er in &report.exploit_refs {
                let cve_str = er.cve.as_deref().unwrap_or("-");
                output.push_str(&format!(
                    "| EDB-{} | {} | {} | {} | `{}` |\n",
                    er.edb_id, cve_str, er.title, er.exploit_type, er.file_path
                ));
            }
            output.push_str("\n");
        }

        output
    }

    pub fn write_to_file(report: &ScanReport, path: &str) -> std::io::Result<()> {
        let markdown = Self::generate(report);
        if let Some(parent) = Path::new(path).parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, markdown)
    }
}
```

- [ ] **Step 3: Write json.rs**

```rust
// crates/reporting/src/json.rs
use aegis_core::types::ScanReport;
use std::path::Path;
use std::fs;

pub struct JsonReport;

impl JsonReport {
    pub fn generate(report: &ScanReport) -> serde_json::Result<String> {
        serde_json::to_string_pretty(report)
    }

    pub fn write_to_file(report: &ScanReport, path: &str) -> Result<(), Box<dyn std::error::Error>> {
        let json = Self::generate(report)?;
        if let Some(parent) = Path::new(path).parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, json)?;
        Ok(())
    }
}
```

- [ ] **Step 4: Write reporting/src/lib.rs**
- [ ] **Step 5: Verify compilation**

```bash
cd /home/ryasr/personal-project/Aegis && cargo build -p aegis-reporting 2>&1
```

- [ ] **Step 6: Commit**

---

### Task 8: Main Binary — CLI Entrypoint

**Files:**
- Create: `src/main.rs`
- Create: `configs/default.toml`

- [ ] **Step 1: Write main.rs**

```rust
// src/main.rs
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;
use anyhow::Result;

use aegis_core::config::AppConfig;
use aegis_core::target::TargetValidator;
use aegis_events::bus::EventBus;
use aegis_recon::registry::PluginRegistry;
use aegis_scheduler::engine::SchedulerEngine;
use aegis_storage::Database;
use aegis_reporting::markdown::MarkdownReport;
use aegis_reporting::json::JsonReport;
use aegis_core::types::ScanReport;

use std::sync::Arc;

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
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Scan { target, format, output, config } => {
            let config: AppConfig = load_config(&config);
            let _parsed_target = TargetValidator::parse(&target)?;
            let db = Arc::new(Database::open(&config.general.db_path)?);
            let event_bus = EventBus::new(1024);
            let registry = PluginRegistry::new();
            let engine = SchedulerEngine::new(config.clone(), event_bus.clone(), db.clone(), registry);

            // Run scan
            let scan_id = engine.run_scan(&_parsed_target.normalized).await?;

            // Build report
            let services = db.get_services_by_scan(&scan_id)?;
            let findings = db.get_findings_by_scan(&scan_id)?;

            let report = ScanReport {
                target: _parsed_target.normalized,
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

            // Write report
            let report_path = output.unwrap_or_else(|| format!("reports/{}.md", scan_id));
            match format.as_str() {
                "json" => JsonReport::write_to_file(&report, &report_path)?,
                _ => MarkdownReport::write_to_file(&report, &report_path)?,
            }

            println!("Report written to: {}", report_path);
            println!("Scan ID: {}", scan_id);
        }
        Commands::Recon { target, config } => {
            let config: AppConfig = load_config(&config);
            let _parsed_target = TargetValidator::parse(&target)?;
            let db = Arc::new(Database::open(&config.general.db_path)?);
            let event_bus = EventBus::new(1024);
            let registry = PluginRegistry::new();
            let engine = SchedulerEngine::new(config, event_bus, db.clone(), registry);

            let scan_id = engine.run_scan(&_parsed_target.normalized).await?;
            println!("Recon complete. Scan ID: {}", scan_id);
        }
        Commands::List => {
            println!("List command not yet implemented");
        }
    }

    Ok(())
}

fn load_config(path: &str) -> AppConfig {
    if let Ok(content) = std::fs::read_to_string(path) {
        toml::from_str(&content).unwrap_or_default()
    } else {
        AppConfig::default()
    }
}
```

- [ ] **Step 2: Write default config**

```toml
# configs/default.toml
[general]
max_concurrency = 0  # 0 = auto-detect from CPU cores
data_dir = "data"
report_dir = "reports"
db_path = "data/aegis.db"

[rate_limits]
requests_per_second = 10
burst_size = 20
max_retries = 3
backoff_base_ms = 1000

[paths]
subfinder = "subfinder"
httpx = "httpx"
nuclei = "nuclei"
katana = "katana"
exploitdb_csv = "data/exploitdb/files_exploits.csv"
exploitdb_dir = "data/exploitdb/"

[plugins]
enabled_plugins = ["subfinder", "httpx", "nuclei", "katana"]
nuclei_severities = ["critical", "high", "medium"]
nuclei_concurrency = 10
httpx_threads = 50
```

- [ ] **Step 3: Build full workspace**

```bash
cd /home/ryasr/personal-project/Aegis && cargo build 2>&1
```

- [ ] **Step 4: Fix any compilation errors**
- [ ] **Step 5: Test basic execution**

```bash
cd /home/ryasr/personal-project/Aegis && cargo run -- --help 2>&1
```

- [ ] **Step 6: Commit**

---

## Spec Coverage Check

| Spec Requirement | Task |
|-----------------|------|
| Rust orchestrator | Task 8 (main.rs) |
| Event bus | Task 2 (events crate) |
| SQLite store | Task 3 (storage crate) |
| Plugin system for tools | Task 4 (recon crate) |
| Exploit intelligence index | Task 5 (intel crate) |
| Tech → exploit matching | Task 5 (correlation.rs) |
| Priority queue system | Task 6 (queue.rs) |
| Adaptive scheduler | Task 6 (engine.rs) |
| Reporting (markdown + json) | Task 7 (reporting crate) |
| CLI interface | Task 8 (main.rs) |
| JS intelligence engine | Phase 2 |
| Historical recon | Phase 2 |
| Continuous monitoring | Phase 2 |
| Attack graph | Phase 2 |
| JWT/API key analysis | Phase 2 |

## Execution Handoff

Plan complete and saved. Two execution options:

**1. Subagent-Driven (recommended)** — I dispatch a fresh agent per task, review between tasks, fast iteration

**2. Inline Execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints

**Which approach?**
