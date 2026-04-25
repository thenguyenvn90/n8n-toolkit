#!/usr/bin/env bash
# tests/run_tests.sh — Test runner for n8n-toolkit bats test suite
# Installs bats-core if not present, then runs all unit + integration tests.
# Supports both the original helpers/ structure and the new test_helper/ structure.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

# ---- Color output helpers ----
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RESET='\033[0m'
info()  { echo -e "${GREEN}[INFO]${RESET}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
error() { echo -e "${RED}[ERROR]${RESET} $*" >&2; }

# ---- Locate or install bats ----
find_or_install_bats() {
    # Already on PATH?
    if command -v bats &>/dev/null; then
        info "bats found at: $(command -v bats) ($(bats --version))"
        return 0
    fi

    # Check local submodule location (tests/bats/bin/bats)
    local local_bats="$SCRIPT_DIR/bats/bin/bats"
    if [[ -x "$local_bats" ]]; then
        export PATH="$SCRIPT_DIR/bats/bin:$PATH"
        info "bats found at: $local_bats"
        return 0
    fi

    # Check other common locations
    for candidate in \
        "/usr/local/bin/bats" \
        "$HOME/.local/bin/bats" \
        "$REPO_ROOT/.bats/bin/bats" \
        "/opt/bats/bin/bats"
    do
        if [[ -x "$candidate" ]]; then
            export PATH="$(dirname "$candidate"):$PATH"
            info "bats found at: $candidate"
            return 0
        fi
    done

    warn "bats not found — attempting installation..."

    # Try npm (fastest on most dev machines)
    if command -v npm &>/dev/null; then
        info "Installing bats via npm..."
        npm install -g bats && return 0
    fi

    # Try apt-get (CI / Debian/Ubuntu)
    if command -v apt-get &>/dev/null; then
        info "Installing bats via apt-get..."
        sudo apt-get install -y bats 2>/dev/null && return 0
    fi

    # Try brew (macOS)
    if command -v brew &>/dev/null; then
        info "Installing bats via brew..."
        brew install bats-core && return 0
    fi

    # Fallback: clone bats-core into tests/bats (matches expected submodule path)
    local BATS_INSTALL_DIR="$SCRIPT_DIR/bats"
    info "Cloning bats-core into $BATS_INSTALL_DIR ..."
    git clone --depth 1 https://github.com/bats-core/bats-core.git "$BATS_INSTALL_DIR" 2>/dev/null \
        || { error "Failed to clone bats-core. Install manually: https://github.com/bats-core/bats-core"; exit 1; }
    export PATH="$BATS_INSTALL_DIR/bin:$PATH"

    if command -v bats &>/dev/null; then
        info "bats installed at: $(command -v bats)"
        return 0
    fi

    error "bats installation failed. Please install manually."
    exit 1
}

# ---- Argument parsing ----
RUN_UNIT=true
RUN_INTEGRATION=true
SPECIFIC_FILE=""
VERBOSE=false
SUITE="all"  # all | original | new

while [[ $# -gt 0 ]]; do
    case "$1" in
        --unit)         RUN_INTEGRATION=false; shift ;;
        --integration)  RUN_UNIT=false; shift ;;
        --file)         SPECIFIC_FILE="$2"; shift 2 ;;
        --verbose|-v)   VERBOSE=true; shift ;;
        --suite)        SUITE="$2"; shift 2 ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "  --unit           Run only unit tests"
            echo "  --integration    Run only integration tests"
            echo "  --file <path>    Run a single .bats file"
            echo "  --verbose        Pass --verbose to bats"
            echo "  --suite all      Run both original and new test suites (default)"
            echo "  --suite original Run original helpers/ tests only"
            echo "  --suite new      Run new test_helper/ tests only"
            exit 0
            ;;
        *)
            error "Unknown option: $1"
            exit 1
            ;;
    esac
done

$VERBOSE && BATS_ARGS="--verbose" || BATS_ARGS="--tap"

# ---- Main ----
cd "$REPO_ROOT"
find_or_install_bats

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║       n8n-toolkit Test Suite (v3.0-rewrite)          ║"
echo "╚══════════════════════════════════════════════════════╝"
echo "  Repo root : $REPO_ROOT"
echo "  bats      : $(bats --version)"
echo "  Suite     : $SUITE"
echo ""

TOTAL_PASS=0
TOTAL_FAIL=0
FAILED_FILES=()

run_suite() {
    local suite_label="$1"
    shift
    local files=("$@")

    for f in "${files[@]}"; do
        [[ -f "$f" ]] || { warn "Skipping missing file: $f"; continue; }
        local label; label="$(basename "$f")"
        echo ""
        echo "──────────────────────────────────────────────────────"
        echo " $suite_label: $label"
        echo "──────────────────────────────────────────────────────"
        if bats $BATS_ARGS "$f"; then
            ((TOTAL_PASS++)) || true
        else
            ((TOTAL_FAIL++)) || true
            FAILED_FILES+=("$f")
        fi
    done
}

# Specific single file mode
if [[ -n "$SPECIFIC_FILE" ]]; then
    if [[ ! -f "$SPECIFIC_FILE" ]]; then
        SPECIFIC_FILE="$REPO_ROOT/$SPECIFIC_FILE"
    fi
    [[ -f "$SPECIFIC_FILE" ]] || { error "File not found: $SPECIFIC_FILE"; exit 1; }
    bats $BATS_ARGS "$SPECIFIC_FILE"
    exit $?
fi

# ---------------------------------------------------------------------------
# Original test suite (tests/helpers/ + tests/unit/ + tests/integration/)
# ---------------------------------------------------------------------------
if [[ "$SUITE" == "all" || "$SUITE" == "original" ]]; then
    if $RUN_UNIT; then
        run_suite "UNIT (original)" \
            "$SCRIPT_DIR/unit/test_common.bats" \
            "$SCRIPT_DIR/unit/test_env_handling.bats" \
            "$SCRIPT_DIR/unit/test_install_wizard.bats" \
            "$SCRIPT_DIR/unit/test_version.bats"
    fi

    if $RUN_INTEGRATION; then
        run_suite "INTEGRATION (original)" \
            "$SCRIPT_DIR/integration/test_install_cli.bats" \
            "$SCRIPT_DIR/integration/test_install_flow.bats" \
            "$SCRIPT_DIR/integration/test_backup_flow.bats" \
            "$SCRIPT_DIR/integration/test_upgrade_flow.bats"
    fi
fi

# ---------------------------------------------------------------------------
# New test suite (tests/test_helper/ structure — bats-core submodule style)
# ---------------------------------------------------------------------------
if [[ "$SUITE" == "all" || "$SUITE" == "new" ]]; then
    if $RUN_UNIT; then
        run_suite "UNIT (new)" \
            "$SCRIPT_DIR/unit/test_parse_domain.bats" \
            "$SCRIPT_DIR/unit/test_env_helpers.bats" \
            "$SCRIPT_DIR/unit/test_wizard_prereqs.bats" \
            "$SCRIPT_DIR/unit/test_arg_parsing.bats"
    fi

    if $RUN_INTEGRATION; then
        run_suite "INTEGRATION (new)" \
            "$SCRIPT_DIR/integration/test_install_flow.bats" \
            "$SCRIPT_DIR/integration/test_backup_flow.bats" \
            "$SCRIPT_DIR/integration/test_upgrade_flow.bats" \
            "$SCRIPT_DIR/integration/test_cleanup_flow.bats"
    fi
fi

# ---- Summary ----
echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║                  Test Summary                        ║"
echo "╚══════════════════════════════════════════════════════╝"
echo "  Files passed : $TOTAL_PASS"
echo "  Files failed : $TOTAL_FAIL"

if (( TOTAL_FAIL > 0 )); then
    echo ""
    echo "  Failed files:"
    for ff in "${FAILED_FILES[@]}"; do
        echo "    - $ff"
    done
    echo ""
    error "One or more test files failed."
    exit 1
fi

echo ""
info "All test files passed."
exit 0
