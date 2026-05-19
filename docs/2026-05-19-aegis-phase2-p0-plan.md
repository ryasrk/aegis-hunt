# Aegis Phase 2 P0 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development

**Goal:** Build JS intelligence engine, wire priority queue, add spawn_blocking for async safety

**Architecture:** New `aegis-jsengine` crate for JS bundle analysis (regex extraction + future tree-sitter AST). Refactor SchedulerEngine to use PriorityQueue. Add async-safe DB wrappers with spawn_blocking.

**Tech Stack:** Rust, reqwest, regex, serde_json, tree-sitter (future)

---

## File Structure

```
crates/jsengine/
├── Cargo.toml
└── src/
    ├── lib.rs
    ├── downloader.rs     # JS bundle fetching via reqwest
    ├── extractor.rs      # Regex pattern extraction
    └── patterns.rs       # All regex patterns for endpoints/secrets/etc.
```

Modified files:
- `crates/scheduler/src/engine.rs` — wire priority queue + JS engine integration
- `crates/scheduler/src/queue.rs` — add From impls for enqueueing
- `crates/storage/src/db.rs` — add spawn_blocking helpers
- `src/main.rs` — register jsengine crate
- `Cargo.toml` — add jsengine member
- `crates/scheduler/Cargo.toml` — add jsengine dep

### Task 1: JS Intelligence Engine Crate

**Files:**
- Create: `crates/jsengine/Cargo.toml`
- Create: `crates/jsengine/src/lib.rs`
- Create: `crates/jsengine/src/downloader.rs`
- Create: `crates/jsengine/src/extractor.rs`
- Create: `crates/jsengine/src/patterns.rs`

**crates/jsengine/Cargo.toml:**
```toml
[package]
name = "aegis-jsengine"
version = "0.1.0"
edition = "2021"

[dependencies]
aegis-core = { path = "../core" }
aegis-events = { path = "../events" }
reqwest = { version = "0.12", features = ["rustls-tls"] }
tokio = { version = "1", features = ["full"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
regex = "1"
tracing = "0.1"
url = "2"
```

**patterns.rs** — All regex patterns for JS bundle extraction:

Define these patterns:
- `API_ENDPOINT` — matches `/api/v1/...`, `/v2/...`, `api.` subdomain refs
- `AWS_KEY` — matches `AKIA[0-9A-Z]{16}` (AWS access key format)
- `GRAPHQL_ENDPOINT` — matches `/graphql`, `/v1/graphql`, `graphql?`
- `WEBSOCKET` — matches `wss://`, `ws://`, `new WebSocket(`
- `POSTMESSAGE` — matches `.postMessage(`, `addEventListener('message'`
- `SOURCEMAP` — matches `//# sourceMappingURL=`, `.map` references
- `CLOUD_BUCKET` — matches `s3://`, `amazonaws.com`, `storage.googleapis.com`, `blob.core.windows.net`
- `INTERNAL_DOMAIN` — matches internal naming patterns: `internal`, `staging`, `dev.`, `localhost`, `10.`, `192.168.`
- `JWT_TOKEN` — matches `eyJ[0-9a-zA-Z_-]+\.eyJ[0-9a-zA-Z_-]+\.[0-9a-zA-Z_-]+`
- `FIREBASE_URL` — matches `*.firebaseio.com`
- `HIDDEN_ENDPOINT` — matches paths with words like `admin`, `debug`, `internal`, `hidden`

**extractor.rs** — Match engine:
```rust
use regex::Regex;
use crate::patterns;

pub struct JsExtractor {
    patterns: Vec<(&'static str, Regex)>,
}

impl JsExtractor {
    pub fn new() -> Self {
        let patterns = vec![
            ("api_endpoint", Regex::new(patterns::API_ENDPOINT).unwrap()),
            ("aws_key", Regex::new(patterns::AWS_KEY).unwrap()),
            // ... all patterns
        ];
        Self { patterns }
    }

    pub fn extract_all(&self, content: &str, url: &str) -> Vec<JsFinding> {
        // Run all patterns, collect results
    }
}

pub struct JsFinding {
    pub extract_type: String,
    pub value: String,
    pub context: String,  // surrounding line
    pub source_url: String,
    pub confidence: u8,
}
```

**downloader.rs** — Fetch JS bundles:
```rust
pub struct JsDownloader {
    client: reqwest::Client,
}

impl JsDownloader {
    pub fn new() -> Self { ... }
    pub async fn download(&self, url: &str) -> Result<String> { ... }
    pub async fn discover_js_urls(&self, html: &str, base_url: &str) -> Vec<String> {
        // Extract <script src="..."> from HTML
    }
}
```

### Task 2: Wire Priority Queue

**Modify `crates/scheduler/src/queue.rs`:**
- Add `QueueItem::new(task_type, target, payload, priority)` constructor
- Add `enqueue_scan_start(scan_id, target)` convenience method
- Add `QueuePriority::from_risk_score(score: u32) -> Self` for automatic prioritization

**Modify `crates/scheduler/src/engine.rs`:**
- SchedulerEngine holds a PriorityQueue
- `run_scan()` enqueues tasks at appropriate priorities:
  - Subdomain enumeration → Fast
  - HTTP probing → Fast
  - URL crawling → Medium
  - JS analysis → Medium
  - Nuclei scanning → Expensive
  - Exploit verification → Expensive
  - Manual validation → Human
- Worker pool loop: `dequeue()` → process → emit events

### Task 3: spawn_blocking for SQLite

**Modify `crates/storage/src/db.rs` and `models.rs`:**
- Add `tokio::sync::Mutex` variant alongside `std::sync::Mutex`
- Or wrap each CRUD method in `tokio::task::spawn_blocking`
- Or add `DatabaseAsync` wrapper that delegates to `Database` via `spawn_blocking`

### Task 4: Integrate JS Engine into Scheduler

**Modify scheduler engine to call JS engine after httpx discovers services:**
- For each HTTP service with JS content-type, download JS bundles
- Run JsExtractor on each bundle
- Store findings via events (JavascriptAssetDiscovered, SecretDetected)
- New findings from JS feed back into priority queue for deeper analysis

---

## Spec Coverage

| Requirement | Task |
|-------------|------|
| JS endpoint extraction | Task 1 (patterns + extractor) |
| Secret scanning in JS | Task 1 (AWS keys, JWT, tokens) |
| JS bundle downloading | Task 1 (downloader via reqwest) |
| Priority queuing | Task 2 |
| spawn_blocking | Task 3 |
| Scheduler integration | Task 4 |
| postMessage detection | Task 1 patterns |
| GraphQL schema discovery | Task 1 patterns |
| Source map references | Task 1 patterns |
| Cloud bucket detection | Task 1 patterns |
| WebSocket endpoint detection | Task 1 patterns |

## Execution Handoff

Plan complete. Two options:

1. **Subagent-Driven** — dispatch per task with review
2. **Inline Execution** — build in this session
