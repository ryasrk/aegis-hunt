# Aegis Progress

## Phase 1 MVP — Complete (2026-05-19)

### Built
- [x] Rust workspace with 8 crates (1970s lines Rust, 28 source files)
- [x] Event bus with 27 typed event variants
- [x] SQLite database with 8 tables, migrations, CRUD
- [x] Plugin system: subfinder, httpx, nuclei subprocess runners
- [x] ExploitDB index: CSV parsing, CVE/tech/platform search (47K entries)
- [x] Correlation engine: tech-to-exploit matching
- [x] Priority queues (Fast/Medium/Expensive/Human)
- [x] Scheduler engine with Phase 1 recon orchestration
- [x] Markdown report generator (severity table, surface table, exploit refs)
- [x] JSON report generator
- [x] CLI with `scan`, `recon`, `list` commands
- [x] TOML configuration
- [x] Target validator with scope enforcement
- [x] 11 unit tests (8 core + 3 storage)
- [x] Zero clippy warnings, clean debug + release build

### Pushed
- [x] GitHub: `github.com/ryasrk/aegis-hunt` (main branch, single squashed commit)

---

## Phase 2 P0 — Complete (2026-05-19)

### JS Intelligence Engine
- [x] 15 regex patterns: API endpoints, AWS keys, JWT, GraphQL, WebSocket, postMessage, source maps, cloud buckets, internal domains, secrets
- [x] JS bundle downloading via reqwest with HTML script discovery
- [x] Line-aware context extraction with confidence scoring
- [x] 12 unit tests covering all pattern types + URL resolution
- [x] Integrated into scheduler: auto-analyzes JS after httpx probing

### Scheduler Improvements
- [x] Priority queue wired into engine (Fast/Medium/Expensive/Human)
- [x] Queue-based task dispatch for subdomain_enum, http_probe, vuln_scan, js_analysis
- [x] spawn_blocking AsyncDatabase wrapper for async-safe SQLite

### Test Coverage
- [x] 23 tests across 3 crates (8 core + 12 jsengine + 3 storage)
- [x] Zero clippy warnings, clean debug + release build

---

## Phase 2 P1 — Planned

### Recon Enhancements
- [ ] JS intelligence engine (tree-sitter AST parsing for endpoints/secrets)
- [ ] Subdomain takeover detection (subjack/digitalocean pattern matching)
- [ ] Gowitness screenshots for all live hosts
- [ ] Historical URL diffing (waybackurls → detect new endpoints)
- [ ] WAF detection (wafw00f integration)
- [ ] CORS misconfiguration testing

### Intel Enhancements
- [ ] Tantivy full-text search for exploit index
- [ ] Version-aware exploit matching (semver range matching)
- [ ] GitHub PoC crawling

### Verification
- [ ] WAF-specific bypass payloads per vendor
- [ ] Interactsh OOB listener for blind SSRF/XSS
- [ ] SSRF probe against cloud metadata
- [ ] LFI payload sequence testing
- [ ] Content discovery cascade (multi-wordlist)

### Scheduler
- [ ] Wire priority queue into engine
- [ ] `spawn_blocking` for all SQLite calls
- [ ] Adaptive rate limiting (backoff on 429/403)
- [ ] Scan duration tracking
- [ ] Progress reporting

### Reporting
- [ ] HTML report with screenshots
- [ ] SARIF output
- [ ] Attack chain suggestions
- [ ] Notify alerts on critical findings

### Monitoring
- [ ] Continuous monitoring mode (`aegis monitor scope.txt`)
- [ ] Periodic passive recon
- [ ] Scheduled verification
- [ ] Asset drift tracking
- [ ] Differential analysis

### Infrastructure
- [ ] Distributed execution (multi-worker)
- [ ] PostgreSQL support option
- [ ] Docker deployment
