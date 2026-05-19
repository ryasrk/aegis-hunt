#!/usr/bin/env bash
set -euo pipefail

AEGIS_DIR="$(cd "$(dirname "$0")" && pwd)"
AEGIS_BIN="$AEGIS_DIR/target/release/aegis"
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

export PATH="$HOME/.cargo/bin:$HOME/go/bin:$PATH"

# ── Ensure binary exists ──────────────────────────────────────────────
if [ ! -f "$AEGIS_BIN" ]; then
    echo -e "${YELLOW}[Aegis]${NC} Binary not found. Building..."
    cd "$AEGIS_DIR"
    cargo build --release 2>&1 | tail -1
fi

# ── Help ──────────────────────────────────────────────────────────────
if [ $# -eq 0 ] || [[ "$1" == "-h" ]] || [[ "$1" == "--help" ]]; then
    echo -e "${CYAN}"
    cat << "EOF"
    ___                  _
   / _ \  __ _  ___  ___(_) ___
  / ___ \/ _` |/ _ \/ __| |/ _ \
 /_/   \__, |  __/\__ \ | (_) |
       |___/ \___||___/_|\___/
EOF
    echo -e "${NC}"
    echo "Usage:"
    echo "  ./run.sh <target>              Full autonomous scan"
    echo "  ./run.sh <target> --quick      Recon only (subfinder + httpx)"
    echo "  ./run.sh <target> --scope s.json  Scan with scope filtering"
    echo "  ./run.sh --serve               Start web dashboard"
    echo "  ./run.sh --monitor <target>    Continuous monitoring"
    echo "  ./run.sh --campaign targets.txt Autonomous campaign"
    echo "  ./run.sh --list                List recent scans"
    echo "  ./run.sh --help                This help"
    echo ""
    echo "Examples:"
    echo "  ./run.sh example.com"
    echo "  ./run.sh example.com --scope configs/scope.example.json"
    echo "  ./run.sh --serve"
    echo "  ./run.sh --monitor example.com --interval 30"
    echo ""
    exit 0
fi

# ── Parse commands ────────────────────────────────────────────────────
case "$1" in
    --serve|-s)
        echo -e "${CYAN}[Aegis]${NC} Starting web dashboard at ${GREEN}http://127.0.0.1:4097/api/dashboard${NC}"
        exec "$AEGIS_BIN" serve --host 0.0.0.0 --port 4097
        ;;

    --monitor|-m)
        TARGET="${2:-}"
        if [ -z "$TARGET" ]; then
            echo -e "${RED}[Aegis]${NC} Usage: ./run.sh --monitor <target> [--interval N]"
            exit 1
        fi
        INTERVAL="${3:-60}"
        echo -e "${CYAN}[Aegis]${NC} Monitoring ${GREEN}$TARGET${NC} every ${YELLOW}${INTERVAL}m${NC}"
        exec "$AEGIS_BIN" monitor "$TARGET" --interval "$INTERVAL"
        ;;

    --campaign|-c)
        TARGETS="${2:-}"
        if [ -z "$TARGETS" ]; then
            echo -e "${RED}[Aegis]${NC} Usage: ./run.sh --campaign targets.txt"
            exit 1
        fi
        echo -e "${CYAN}[Aegis]${NC} Running autonomous campaign on targets from ${GREEN}$TARGETS${NC}"
        exec "$AEGIS_BIN" auto "$TARGETS"
        ;;

    --list|-l)
        exec "$AEGIS_BIN" list
        ;;

    --recon|-r)
        TARGET="${2:-}"
        if [ -z "$TARGET" ]; then
            echo -e "${RED}[Aegis]${NC} Usage: ./run.sh --recon <target>"
            exit 1
        fi
        echo -e "${CYAN}[Aegis]${NC} Recon on ${GREEN}$TARGET${NC}"
        exec "$AEGIS_BIN" recon "$TARGET"
        ;;

    *)
        TARGET="$1"
        shift
        SCOPE=""
        FORMAT="markdown"

        while [ $# -gt 0 ]; do
            case "$1" in
                --scope) SCOPE="$2"; shift ;;
                --quick) FORMAT="markdown" ;;
                --json)  FORMAT="json" ;;
                *)       break ;;
            esac
            shift
        done

        echo -e "${CYAN}[Aegis]${NC} Scanning ${GREEN}$TARGET${NC}"
        if [ -n "$SCOPE" ]; then
            echo -e "${CYAN}[Aegis]${NC} Scope file: ${YELLOW}$SCOPE${NC}"
            exec "$AEGIS_BIN" scan "$TARGET" --format "$FORMAT" --scope "$SCOPE"
        else
            exec "$AEGIS_BIN" scan "$TARGET" --format "$FORMAT"
        fi
        ;;
esac
