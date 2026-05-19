#!/usr/bin/env bash
set -euo pipefail

AEGIS_DIR="$(cd "$(dirname "$0")" && pwd)"
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

log()  { echo -e "${CYAN}[Aegis]${NC} $1"; }
ok()   { echo -e "${GREEN}[  OK]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; }

export PATH="$HOME/.cargo/bin:$HOME/go/bin:/usr/local/go/bin:$PATH"

# ── Header ────────────────────────────────────────────────────────────
echo -e "${CYAN}"
cat << "EOF"
    ___                  _
   / _ \  __ _  ___  ___(_) ___
  / ___ \/ _` |/ _ \/ __| |/ _ \
 /_/   \_\__, |  __/\__ \ | (_) |
         |___/ \___||___/_|\___/
 Recon Intelligence Platform
EOF
echo -e "${NC}"

# ── Phase 0: OS Detection ─────────────────────────────────────────────
log "Detecting operating system..."
OS="$(uname -s)"
ARCH="$(uname -m)"
log "Running on ${OS}/${ARCH}"

# ── Phase 1: System Dependencies ──────────────────────────────────────
log "Checking system dependencies..."

MISSING_SYS=()
for cmd in curl git make gcc pkg-config; do
    command -v "$cmd" &>/dev/null || MISSING_SYS+=("$cmd")
done

if [ ${#MISSING_SYS[@]} -gt 0 ]; then
    warn "Missing system tools: ${MISSING_SYS[*]}"
    if [[ "$OS" == "Linux" ]]; then
        log "Installing via apt..."
        sudo apt-get update -qq && sudo apt-get install -y -qq "${MISSING_SYS[@]}" libssl-dev 2>/dev/null
    elif [[ "$OS" == "Darwin" ]]; then
        log "Installing via brew..."
        brew install "${MISSING_SYS[@]}" openssl 2>/dev/null
    else
        fail "Please install: ${MISSING_SYS[*]}"
    fi
fi
ok "System dependencies ready"

# ── Phase 2: Rust ─────────────────────────────────────────────────────
log "Checking Rust toolchain..."
if ! command -v cargo &>/dev/null; then
    warn "Rust not found. Installing via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
    source "$HOME/.cargo/env"
fi

RUST_VER=$(rustc --version 2>/dev/null || echo "none")
log "Rust: ${RUST_VER}"
ok "Rust ready"

# ── Phase 3: Go Tools ─────────────────────────────────────────────────
log "Checking Go toolchain..."
if ! command -v go &>/dev/null; then
    warn "Go not found. Some scanning tools (subfinder, httpx, nuclei) won't be available."
    warn "Install Go from: https://go.dev/dl/"
else
    GO_VER=$(go version 2>/dev/null || echo "none")
    log "Go: ${GO_VER}"

    GO_TOOLS=(subfinder httpx nuclei katana gau waybackurls unfurl dnsx notify)
    log "Checking Go security tools..."
    for tool in "${GO_TOOLS[@]}"; do
        if ! command -v "$tool" &>/dev/null; then
            warn "$tool not found. Install with: go install -v github.com/projectdiscovery/${tool}/cmd/${tool}@latest"
        fi
    done
fi
ok "Go tools checked"

# ── Phase 4: Build Aegis ──────────────────────────────────────────────
log "Building Aegis..."
cd "$AEGIS_DIR"
cargo build --release 2>&1 | tail -1
ok "Aegis built: target/release/aegis ($(du -h target/release/aegis | cut -f1))"

# ── Phase 5: Create Data Directories ──────────────────────────────────
mkdir -p data/exploitdb reports configs
if [ -f /home/ryasr/cvekb/files_exploits.csv ]; then
    log "Found exploit-db CSV at ~/cvekb/"
    ln -sf /home/ryasr/cvekb/files_exploits.csv data/exploitdb/files_exploits.csv 2>/dev/null
    ok "ExploitDB linked"
else
    warn "ExploitDB CSV not found (optional — Aegis works without it)"
fi

# ── Phase 6: Shell Completions ────────────────────────────────────────
log "Generating shell completions..."
mkdir -p completions
target/release/aegis --help > /dev/null 2>&1
ok "Aegis is operational"

# ── Summary ───────────────────────────────────────────────────────────
echo ""
log "${GREEN}Setup complete!${NC}"
echo ""
echo -e "  ${CYAN}USAGE:${NC}"
echo -e "  ./run.sh target.com        ${YELLOW}# Full scan${NC}"
echo -e "  ./run.sh --serve            ${YELLOW}# Start web dashboard${NC}"
echo -e "  aegis scan target.com       ${YELLOW}# Direct usage${NC}"
echo -e "  aegis serve                 ${YELLOW}# Dashboard at :4097${NC}"
echo ""
log "Happy hunting!"
