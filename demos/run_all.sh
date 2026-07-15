#!/usr/bin/env bash
# =============================================================================
# ICEBOX Demo Suite — Master Runner
# =============================================================================
# Run all 5 demos sequentially. Each demo is self-contained and can also be
# run individually. Some demos require Ollama for full functionality.
#
# Usage:
#   ./run_all.sh                    # Run all demos interactively
#   ./run_all.sh --non-interactive  # Run all demos without pausing
#   ./01_vuln_scanner.sh            # Run a single demo
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT" || exit 1

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'
BOLD='\033[1m'

NON_INTERACTIVE=false
if [ "$1" = "--non-interactive" ]; then
    NON_INTERACTIVE=true
    # Simulate ENTER key presses for all read prompts
    export READ_DELAY=0.5
fi

echo ""
echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║${NC}                                                              ${BLUE}║${NC}"
echo -e "${BLUE}║${NC}  ██╗ ██████╗███████╗██████╗  ██████╗ ██╗  ██╗             ${BLUE}║${NC}"
echo -e "${BLUE}║${NC}  ██║██╔════╝██╔════╝██╔══██╗██╔═══██╗╚██╗██╔╝             ${BLUE}║${NC}"
echo -e "${BLUE}║${NC}  ██║██║     █████╗  ██████╔╝██║   ██║ ╚███╔╝              ${BLUE}║${NC}"
echo -e "${BLUE}║${NC}  ██║██║     ██╔══╝  ██╔══██╗██║   ██║ ██╔██╗              ${BLUE}║${NC}"
echo -e "${BLUE}║${NC}  ██║╚██████╗███████╗██████╔╝╚██████╔╝██╔╝ ██╗             ${BLUE}║${NC}"
echo -e "${BLUE}║${NC}  ╚═╝ ╚═════╝╚══════╝╚═════╝  ╚═════╝ ╚═╝  ╚═╝             ${BLUE}║${NC}"
echo -e "${BLUE}║${NC}                                                              ${BLUE}║${NC}"
echo -e "${BLUE}║${NC}  Runtime Governance for Autonomous Offensive Security        ${BLUE}║${NC}"
echo -e "${BLUE}║${NC}  Demo Suite — 5 scenarios                                    ${BLUE}║${NC}"
echo -e "${BLUE}║${NC}                                                              ${BLUE}║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check if built
if [ ! -f "target/debug/icebox-cli" ]; then
    echo -e "${YELLOW}Building ICEBOX CLI...${NC}"
    cargo build -p icebox-cli 2>&1 | tail -3
    echo ""
fi

# Verify cargo is available
if ! command -v cargo &>/dev/null; then
    echo -e "${RED}Error: cargo not found. Install Rust: https://rustup.rs/${NC}"
    exit 1
fi

DEMOS=(
    "01_vuln_scanner: Vulnerability Scanner — Governed by ICEBOX"
    "02_multi_agent_campaign: Multi-Agent Campaign — Orchestrated Governance"
    "03_policy_blocking: Policy Engine — Blocking Dangerous Actions"
    "04_continuous_validation: Continuous Validation — Detecting Policy Drift"
    "05_approval_workflow: Approval Workflow — Request → Approve → Execute"
)

echo -e "${BOLD}Demo Suite Overview:${NC}"
echo ""
for demo in "${DEMOS[@]}"; do
    num="${demo%%:*}"
    desc="${demo#*:}"
    echo -e "  ${GREEN}${num}${NC}  ${desc}"
done
echo ""
echo -e "Estimated time: ~15-20 minutes (interactive) / ~5 minutes (--non-interactive)"
echo ""

if [ "$NON_INTERACTIVE" = false ]; then
    echo -e "${YELLOW}Press ENTER to begin the demo suite...${NC}"
    read -r
fi

# Track timing
START_TIME=$(date +%s)
FAILURES=0

for demo in "${DEMOS[@]}"; do
    num="${demo%%:*}"
    script="$SCRIPT_DIR/${num}.sh"

    if [ ! -f "$script" ]; then
        echo -e "${RED}Script not found: $script${NC}"
        FAILURES=$((FAILURES + 1))
        continue
    fi

    DEMO_START=$(date +%s)
    echo ""
    echo -e "${BLUE}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}  Starting Demo ${num}...${NC}"
    echo -e "${BLUE}══════════════════════════════════════════════════════════════${NC}"
    echo ""

    if [ "$NON_INTERACTIVE" = true ]; then
        # Auto-answer all prompts
        bash "$script" 2>&1 | sed 's/^/  /'
    else
        bash "$script"
    fi

    EXIT_CODE=$?
    DEMO_ELAPSED=$(($(date +%s) - DEMO_START))

    if [ $EXIT_CODE -ne 0 ]; then
        echo -e "${RED}Demo ${num} failed (exit code: $EXIT_CODE)${NC}"
        FAILURES=$((FAILURES + 1))
    else
        echo ""
        echo -e "${GREEN}✓ Demo ${num} completed in ${DEMO_ELAPSED}s${NC}"
    fi

    echo ""
    if [ "$NON_INTERACTIVE" = false ]; then
        echo -e "${YELLOW}Press ENTER to continue to the next demo...${NC}"
        read -r
    fi
done

TOTAL_ELAPSED=$(($(date +%s) - START_TIME))

echo ""
echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║${NC}              Demo Suite Complete                           ${BLUE}║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  Total time: ${TOTAL_ELAPSED}s"
echo -e "  Demos run: ${#DEMOS[@]}"
echo -e "  Failures: $FAILURES"
echo ""
echo -e "  ${BOLD}Artifacts produced:${NC}"
echo -e "  • /tmp/icebox_audit.csv"
echo -e "  • /tmp/icebox_audit.json"
echo -e "  • /tmp/icebox_baseline.json"
echo -e "  • /tmp/icebox_modified.json"
echo -e "  • /tmp/icebox_campaign_audit.csv"
echo -e "  • /tmp/icebox_campaign_audit.json"
echo -e "  • /tmp/icebox_approval_audit.csv"
echo -e "  • /tmp/icebox_approval_audit.json"
echo ""

if [ $FAILURES -eq 0 ]; then
    echo -e "${GREEN}${BOLD}All demos completed successfully!${NC}"
    echo ""
    echo -e "  Ready for video recording. Suggested narration structure:"
    echo -e "  1. What is ICEBOX? (30s — architecture slide)"
    echo -e "  2. Demo 1: Vulnerability scanner (2 min)"
    echo -e "  3. Demo 3: Policy blocking (1.5 min)"
    echo -e "  4. Demo 5: Approval workflow (2 min)"
    echo -e "  5. Demo 4: Continuous validation (1.5 min)"
    echo -e "  6. Demo 2: Multi-agent campaign (2 min — optional, requires Ollama)"
    echo -e "  Total: ~10 minutes"
else
    echo -e "${RED}${FAILURES} demo(s) had issues. Check output above.${NC}"
    exit 1
fi
echo ""
