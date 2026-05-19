# Aegis — Recon Intelligence Platform

High-performance reconnaissance, intelligence correlation, verification, and reporting platform for authorized bug bounty and attack-surface analysis.

**Core principle:** Maximum intelligence per request.

## Architecture

```text
                    +----------------------+
                    |      Scheduler       |
                    +----------------------+
                               |
       -------------------------------------------------
       |                |               |              |
       v                v               v              v
+-------------+ +-------------+ +-------------+ +--------------+
| Recon Engine| | Fingerprint | | Intel Engine| | Verify Engine|
+-------------+ +-------------+ +-------------+ +--------------+
        \             |               |              /
         -------------------------------------------------
                                |
                                v
                     +----------------------+
                     |   Evidence Store     |
                     |   (SQLite)           |
                     +----------------------+
                                |
                                v
                     +----------------------+
                     |  Reporting Engine    |
                     +----------------------+
```

## Phase 1 MVP (Current)

8-crate Rust workspace:

| Crate | Description |
|-------|-------------|
| `aegis-core` | Types, config, errors, target validation |
| `aegis-events` | EventBus (tokio broadcast, 27 event types) |
| `aegis-storage` | SQLite with 8 tables, migrations, CRUD |
| `aegis-recon` | Plugin system: subfinder, httpx, nuclei runners |
| `aegis-intel` | ExploitDB index (47K entries), tech/CVE correlation |
| `aegis-scheduler` | Priority queues, scan orchestration |
| `aegis-reporting` | Markdown + JSON report generators |
| `aegis` (binary) | CLI: `scan`, `recon`, `list` commands |

## Quick Start

```bash
# Scan a target
cargo run -- scan example.com

# Recon only
cargo run -- recon example.com

# JSON output
cargo run -- scan example.com -f json -o report.json

# Custom config
cargo run -- scan example.com -c configs/custom.toml
```

## CLI

```
Usage: aegis <COMMAND>

Commands:
  scan   Run a full scan against a target
  recon  Run recon only (subfinder + httpx)
  list   List previous scans from the database
  help   Print this message or the help of the given subcommand(s)
```

## Requirements

- Rust 1.75+
- Go tools in PATH: `subfinder`, `httpx`, `nuclei`
- (Optional) ExploitDB CSV at `data/exploitdb/files_exploits.csv`

## Build

```bash
cargo build --release
```

## License

MIT
