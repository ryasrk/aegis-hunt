# Aegis Progress

## Phase 1 — Complete
- [x] Rust workspace with 8 crates (core, events, storage, recon, intel, scheduler, reporting, binary)
- [x] Event bus with 27 typed event variants
- [x] SQLite database with 8 tables, migrations, CRUD
- [x] Plugin system: subfinder, httpx, nuclei subprocess runners
- [x] ExploitDB index: 47K entries with CVE/tech/platform search
- [x] Scheduler engine with recon orchestration
- [x] Priority queues (Fast/Medium/Expensive/Human)
- [x] Markdown + JSON report generators
- [x] CLI with `scan`, `recon`, `list` commands
- [x] Target validator with scope enforcement
- [x] 11 unit tests

## Phase 2 — Complete

### JS Intelligence Engine
- [x] 15 regex patterns: API endpoints, AWS keys, JWT, GraphQL, WebSocket, postMessage, source maps, cloud buckets, internal domains, secrets
- [x] JS bundle downloading via reqwest with HTML script discovery
- [x] Line-aware context extraction with confidence scoring
- [x] 12 unit tests covering all pattern types
- [x] Integrated into scheduler: auto-analyzes JS after httpx probing

### Detection & Verification Modules
- [x] **WAF detection**: 8 vendor fingerprints (Cloudflare, AWS WAF, Akamai, ModSecurity, F5, Imperva, Sucuri) + per-vendor XSS/SQLi bypass payloads
- [x] **SSRF probing**: 14 cloud metadata/internal endpoints with async parameter testing
- [x] **CORS testing**: Reflective origin, wildcard, and credential checks with severity grading
- [x] **LFI probing**: 26 payloads (path traversal, PHP wrappers, file://) with 10 detection indicators
- [x] **Subdomain takeover**: 20 cloud service CNAME fingerprints + HTTP 404 response analysis
- [x] **Content discovery cascade**: 3-level ffuf command generation (common → raft-medium → API endpoints)

### Advanced Hunting Intelligence
- [x] **Tech-specific attack profiles**: 10 technologies (Next.js, GraphQL, Spring, Laravel, Rails, WordPress, Apache, K8s, Jira) with per-test curl examples
- [x] **JWT analyzer**: Detects alg:none, KID injection, privilege claims, expired/future/never-expiring tokens
- [x] **Business logic endpoint classifier**: 12 categories (Auth, Payment, 2FA, File Upload, Admin, SSRF, etc.)
- [x] **Cloud intelligence**: AWS/GCP/Azure checks for metadata service, storage buckets, misconfigurations
- [x] **Parameter vulnerability classifier**: 30 parameter names mapped to likely vulns with confidence scores and payloads
- [x] **Attack chain engine**: 8 chain patterns (SSRF+IDOR, XSS+CORS, LFI+SSRF, SSTI→RCE, redirect+OAuth, etc.)

### Scheduling & Performance
- [x] Priority queue wired into engine with queue-based task dispatch
- [x] AsyncDatabase wrapper with tokio::spawn_blocking for safe SQLite
- [x] Adaptive rate limiting with exponential backoff
- [x] Scan duration tracking and progress logging
- [x] Notify alerts on critical/high findings via `notify` CLI

### Reports
- [x] HTML report generator (dark theme, severity summary, evidence, exploit refs)
- [x] SARIF 2.1.0 output (OASIS standard, severity-to-level mapping)
- [x] Attack chain suggestions in reports

### Monitoring & Deployment
- [x] Continuous monitoring mode (`aegis monitor` with configurable interval)
- [x] Historical recon diffing (adds/removes detection per iteration)
- [x] Dockerfile (multi-stage, 1.75-slim builder → bookworm-slim runtime)

### Test Coverage
- [x] **82 tests across 10 crates** (8 core + 3 storage + 12 jsengine + 12 verify + 27 hunter + 6 ratelimit + 4 monitor + 3 chains + X reporting)
- [x] Zero clippy warnings, clean debug + release build

## Repository
- [x] GitHub: `github.com/ryasrk/aegis-hunt` (main branch)
- [x] README with architecture, quick start, CLI reference
- [x] Full docs/ directory with specs, plans, and progress tracking
