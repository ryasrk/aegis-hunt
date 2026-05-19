# Aegis Dashboard — Design Reference

> Document for redesign purposes. Covers all API endpoints, data structures, UI views, and integration points.

---

## 1. Architecture

```
Browser (Vue.js SPA)
    │
    ├── /api/dashboard  →  Serves index.html (embedded Vue app)
    ├── /api/stats      →  Scan/finding statistics
    ├── /api/scope      →  IN SCOPE / OUT OF SCOPE config (GET/PUT)
    ├── /api/settings   →  LLM + notification config (GET/PUT)
    ├── /api/scans      →  Scan history list
    ├── /api/scan       →  POST new scan
    ├── /api/findings   →  All findings across scans
    ├── /api/graph      →  Attack graph data
    ├── /health         →  Health check
    └── /scan/{id}      →  Single scan details
```

**Backend:** axum 0.7 server on port 4097 (default)
**Frontend:** Vue.js 3 via CDN, vanilla CSS, no build step
**State:** Rust Arc\<Mutex\> on backend, reactive refs on frontend

---

## 2. API Endpoints — Full Reference

### `GET /api/dashboard`
Serves the HTML dashboard page. The HTML file is embedded in the Rust binary via `include_str!("../static/dashboard.html")`.

**No JSON response** — returns `text/html`.

---

### `GET /api/stats`
Returns aggregated scan statistics.

**Response:**
```json
{
  "total_scans": 42,
  "critical": 3,
  "high": 7,
  "medium": 12,
  "domains": 15
}
```

**Backend implementation:** Queries `scans` and `findings` tables from SQLite.

---

### `GET /api/scope`
Returns current IN SCOPE and OUT OF SCOPE configuration.

**Response:**
```json
{
  "in_scope": ["*.example.com", "api.example.org"],
  "out_of_scope": ["pay.example.com", "admin.example.com"]
}
```

---

### `PUT /api/scope`
Updates the scope configuration.

**Request body:**
```json
{
  "in_scope": ["*.example.com"],
  "out_of_scope": ["pay.example.com"]
}
```

**Response:**
```json
{ "status": "saved" }
```

**Storage:** In-memory `Arc<Mutex<ScopeConfig>>` — not persisted to disk currently. The frontend should trigger a save/reload pattern.

---

### `GET /api/settings`
Returns current application settings.

**Response:**
```json
{
  "llm": {
    "endpoint": "https://api.openai.com/v1",
    "api_key": "",
    "model": "gpt-4",
    "temperature": 0.7
  },
  "slack_webhook": "",
  "discord_webhook": "",
  "telegram_token": "",
  "telegram_chat": ""
}
```

---

### `PUT /api/settings`
Updates application settings.

**Request body:** Same structure as GET response.

**Response:**
```json
{ "status": "saved" }
```

---

### `GET /api/scans`
Returns all scan records ordered by most recent first.

**Response:**
```json
{
  "scans": [
    {
      "id": "uuid-string",
      "target": "example.com",
      "started_at": "2026-05-19T12:00:00+00:00",
      "completed_at": "2026-05-19T12:15:00+00:00",
      "status": "completed",
      "duration_secs": 900,
      "finding_count": 5,
      "critical_count": 1,
      "high_count": 2
    }
  ]
}
```

**Backend:** Queries `scans` table via `list_scans()` in models.rs. Finding counts are computed by querying `findings` table grouped by `scan_id`.

---

### `POST /api/scan`
Initiates a new scan.

**Request body:**
```json
{
  "target": "example.com"
}
```

**Response:**
```json
{
  "scan_id": "uuid-string",
  "target": "example.com",
  "status": "running"
}
```

**Backend:** Uses `SchedulerEngine::run_scan()` in a `tokio::spawn` background task.

---

### `GET /api/findings`
Returns all findings across all scans, ordered by severity (critical first) then discovery time.

**Response:**
```json
{
  "findings": [
    {
      "id": "uuid",
      "service_id": null,
      "endpoint_id": null,
      "title": "SQL Injection in login",
      "severity": "CRITICAL",
      "confidence": 90,
      "description": "Description text",
      "evidence": null,
      "cve": "CVE-2024-0001",
      "edb_id": null,
      "remediation": "Use parameterized queries",
      "discovered_at": "2026-05-19T12:00:00+00:00"
    }
  ],
  "total": 42,
  "critical": 3,
  "high": 7,
  "medium": 12,
  "low": 20
}
```

**Backend:** Queries `findings` table via `get_all_findings()` in models.rs. Returns everything sorted by severity.

---

### `GET /api/graph`
Returns attack graph data with nodes, edges, and chain analysis.

**Response:**
```json
{
  "nodes": [
    {"id": "domain-example.com", "type": "domain", "label": "example.com"},
    {"id": "sub-api.example.com", "type": "subdomain", "label": "api.example.com"},
    {"id": "finding-sqli", "type": "finding", "label": "SQL Injection", "severity": "CRITICAL"}
  ],
  "edges": [
    {"source": "domain-example.com", "target": "sub-api.example.com", "relation": "resolves_to"},
    {"source": "finding-sqli", "target": "sub-api.example.com", "relation": "affects"}
  ],
  "chains": [
    {
      "name": "SQL Injection → Data Exfiltration",
      "severity": "CRITICAL",
      "steps": [
        "Exploit SQL injection to extract database",
        "Extract admin credentials",
        "Login as admin",
        "Escalate to RCE"
      ]
    }
  ]
}
```

---

### `GET /health`
Simple health check.

**Response:**
```json
{ "status": "ok", "version": "0.1.0" }
```

---

## 3. UI Views & Layout

### Navigation
Left sidebar with 6 items:
| Icon | Label | View ID |
|------|-------|---------|
| 📊 | Dashboard | `dashboard` |
| 🎯 | Scope | `scope` |
| 🔍 | Scans | `scans` |
| ⚠️ | Findings | `findings` |
| 🔗 | Attack Graph | `graph` |
| ⚙️ | Settings | `settings` |

### View 1: Dashboard
```
┌─────────────────────────────────────────────────────┐
│  [📊 5] [🔴 3] [🟠 7] [🔵 12] [🌐 15]            │  ← stat cards
├─────────────────────────────────────────────────────┤
│  Recent Activity                                     │
│  • Last scan: example.com (5 findings) 2h ago       │
│  • Active campaigns: 1                               │
│  • Total domains in scope: 3                         │
└─────────────────────────────────────────────────────┘
```

**Stat cards displayed:**
1. Total Scans (accent blue)
2. Critical findings (red)
3. High findings (orange)
4. Medium findings (blue)
5. Domains in scope

### View 2: Scope Management
```
┌─────────────────────────────────────────────────────┐
│  IN SCOPE                          [+ Add]          │
│  ┌──────────────────────────────────────────────┐   │
│  │ *.example.com                          [×]   │   │
│  │ api.example.com                        [×]   │   │
│  └──────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────┤
│  OUT OF SCOPE                      [+ Add]          │
│  ┌──────────────────────────────────────────────┐   │
│  │ pay.example.com                         [×]   │   │
│  │ admin.example.com                       [×]   │   │
│  └──────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────┤
│  [Save Scope]  [Reset]                               │
└─────────────────────────────────────────────────────┘
```

**Pattern matching rules:**
- `*.example.com` → matches any subdomain of example.com AND example.com itself
- `example.com` → exact match only (also matches sub.example.com)
- Wildcard is the only special pattern — everything else is exact/subdomain match

### View 3: Scans
```
┌─────────────────────────────────────────────────────┐
│  New Scan: [example.com___________] [Scan]          │
├─────────────────────────────────────────────────────┤
│  Scan History                                        │
│  ┌────────┬──────────┬──────────┬───────┬────────┐  │
│  │ ID     │ Target   │ Findings │ Time  │ Status │  │
│  ├────────┼──────────┼──────────┼───────┼────────┤  │
│  │ a1b2c3 │ ex.com   │ 5 (1🔴2🟠)│ 15m   │ ✅     │  │
│  │ d4e5f6 │ api.ex   │ 2 (1🟠)   │ 8m    │ ✅     │  │
│  └────────┴──────────┴──────────┴───────┴────────┘  │
└─────────────────────────────────────────────────────┘
```

### View 4: Findings
```
┌─────────────────────────────────────────────────────┐
│  [Search findings...]              [Severity ▾]     │
├─────────────────────────────────────────────────────┤
│  ┌────────┬──────────────────┬──────────┬─────────┐ │
│  │ Sev    │ Title            │ Endpoint │ Date    │ │
│  ├────────┼──────────────────┼──────────┼─────────┤ │
│  │ 🔴     │ SQL Injection    │ /api/use │ 05-19   │ │
│  │ 🟠     │ XSS in profile   │ /profile │ 05-19   │ │
│  │ 🔵     │ CORS misconfig  │ /api     │ 05-19   │ │
│  └────────┴──────────────────┴──────────┴─────────┘ │
└─────────────────────────────────────────────────────┘
```

### View 5: Attack Graph
```
┌─────────────────────────────────────────────────────┐
│  Nodes: 12  Edges: 18  Risk Score: 720/1000        │
├─────────────────────────────────────────────────────┤
│  Vulnerability Chains                                │
│  🔴 SQL Injection → Data Exfiltration               │
│    1. Exploit SQL injection to extract database      │
│    2. Extract admin credentials from users table     │
│    3. Login as admin via extracted credentials       │
│  ────────────────────────────────────────────────   │
│  🔴 SSRF → Cloud Metadata → Credential Theft        │
│    1. Identify injectable URL parameter              │
│    2. Inject cloud metadata URL                      │
│    3. Extract IAM credentials from response          │
└─────────────────────────────────────────────────────┘
```

### View 6: Settings
```
┌─────────────────────────────────────────────────────┐
│  LLM Configuration                                   │
│  Endpoint:  [https://api.openai.com/v1___________]  │
│  API Key:   [••••••••••••••••••••••••••••••••]     │
│  Model:     [gpt-4_______________________________]  │
│  Temp:      [0.7________________________________]  │
│  [Save LLM Config]                                   │
├─────────────────────────────────────────────────────┤
│  Notifications                                       │
│  Slack Webhook:    [https://hooks.slack.com/...]    │
│  Discord Webhook:  [https://discord.com/api/...]    │
│  Telegram Token:   [bot12345:...________________]   │
│  Telegram Chat ID: [-123456______________________]  │
│  [Save Notifications]                                │
└─────────────────────────────────────────────────────┘
```

---

## 4. Color Palette (Dark Theme)

| Token | Hex | Usage |
|-------|-----|-------|
| `--bg` | `#0d1117` | Page background |
| `--surface` | `#161b22` | Cards, sidebar, table rows |
| `--border` | `#30363d` | Borders, dividers |
| `--text` | `#c9d1d9` | Primary text |
| `--text-secondary` | `#8b949e` | Labels, secondary text |
| `--accent` | `#58a6ff` | Links, headings, buttons |
| `--critical` | `#f85149` | Critical severity |
| `--high` | `#d29922` | High severity |
| `--medium` | `#58a6ff` | Medium severity |
| `--low` | `#8b949e` | Low severity |
| `--success` | `#3fb950` | Positive states, in-scope |

---

## 5. Data Structures (from Rust backend)

### `ScopeConfig` (core/src/target.rs)
```rust
pub struct ScopeConfig {
    pub in_scope: Vec<String>,      // e.g. ["*.example.com"]
    pub out_of_scope: Vec<String>,  // e.g. ["pay.example.com"]
}
```

### `AppSettings` (api/src/dashboard.rs)
```rust
pub struct AppSettings {
    pub llm: LlmConfig,              // endpoint, api_key, model, temperature
    pub slack_webhook: String,
    pub discord_webhook: String,
    pub telegram_token: String,
    pub telegram_chat: String,
}

pub struct LlmConfig {
    pub endpoint: String,   // "https://api.openai.com/v1"
    pub api_key: String,    // "sk-..."
    pub model: String,      // "gpt-4"
    pub temperature: f64,   // 0.0 - 2.0
}
```

### `Finding` (core/src/types.rs)
```rust
pub struct Finding {
    pub id: String,
    pub service_id: Option<String>,
    pub endpoint_id: Option<String>,
    pub title: String,
    pub severity: Severity,  // Critical|High|Medium|Low|Info
    pub confidence: u8,      // 0-100
    pub description: String,
    pub evidence: Option<String>,
    pub cve: Option<String>,
    pub edb_id: Option<u32>,
    pub remediation: Option<String>,
    pub discovered_at: DateTime<Utc>,
}
```

### `ScanRecord` (storage/src/models.rs)
```rust
pub struct ScanRecord {
    pub id: String,
    pub target: String,
    pub started_at: String,   // RFC 3339
    pub completed_at: Option<String>,
    pub status: String,       // "running" | "completed"
    pub duration_secs: Option<u64>,
}
```

---

## 6. Current Frontend Implementation

**Stack:** Vue.js 3 via CDN (`https://unpkg.com/vue@3/dist/vue.global.prod.js`)
**Build:** None — single HTML file, no bundler
**State management:** Vue 3 Composition API (refs + reactive)
**HTTP:** `fetch()` with manual error handling

**File location:** `crates/api/static/dashboard.html`
**Embedded in binary:** Yes — via `include_str!("../static/dashboard.html")`
**Served at:** `GET /api/dashboard`

### Vue.js Setup Pattern
```javascript
const { createApp, ref, reactive, computed } = Vue;
createApp({ setup() { ... } }).mount('#app');
```

### API Call Pattern
```javascript
async function apiCall(path, method = 'GET', body = null) {
    const opts = { method, headers: { 'Content-Type': 'application/json' } };
    if (body) opts.body = JSON.stringify(body);
    const resp = await fetch(path, opts);
    return await resp.json();
}
```

---

## 7. Integration Points for Redesign

When redesigning the dashboard, these are all the touch points:

1. **HTML template** — Replace `#app` div content, keep Vue.js reactive bindings
2. **CSS variables** — Update `:root` variables for different theme
3. **API calls** — All go through `apiCall()` helper — can add auth, error handling, retry logic
4. **Navigation** — `navItems` array controls sidebar — add/remove views here
5. **Scope management** — `addScope()`/`removeScope()`/`saveScope()` — extend for categories, tags
6. **Scan flow** — `startScan()` calls `POST /api/scan` — can add scope picker, options
7. **Settings** — `LLM` + `Notifications` sections — add more config sections as desired
8. **Real-time updates** — Dashboard currently polls on load. For live updates, use the SSE endpoint: `GET /scan/{id}/events`
9. **Finding actions** — Add verify, report, dismiss buttons per finding row
10. **Graph visualization** — Currently table-based. For visual graph, integrate D3.js or vis-network

---

## 8. SSE (Server-Sent Events) for Real-Time

Available at `GET /scan/{id}/events` — streams scan lifecycle events:

```
event: message
data: {"scan_id":"...","phase":"recon","subdomains_found":42}

event: message
data: {"scan_id":"...","type":"finding","title":"SQL Injection","severity":"HIGH"}
```

To use in Vue:
```javascript
const source = new EventSource(`/api/scan/${scanId}/events`);
source.onmessage = (event) => {
    const data = JSON.parse(event.data);
    // Update reactive state
};
```

---

## 9. Key Design Notes for Redesign

- **Dark theme only** currently — `system preference` support can be added via CSS `prefers-color-scheme`
- **No authentication** — dashboard is open on the bound interface. Add auth middleware if exposed publicly
- **Mobile responsive** — sidebar collapses on narrow screens. The layout uses `var(--sidebar): 240px` which can become a hamburger menu
- **Loading states** — basic loading text shown during API calls. Add spinners/skeletons for production
- **Error handling** — `apiCall()` catches errors and returns `{ error: message }`. Add toast notifications for UX
- **The Vue SPA is embedded in the Rust binary** — any HTML/JS change requires recompiling with `cargo build`
- **For rapid dashboard iteration** during redesign, serve the HTML file separately (outside the binary) during development, then embed it for production
