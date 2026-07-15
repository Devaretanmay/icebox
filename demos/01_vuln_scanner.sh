#!/usr/bin/env bash
# =============================================================================
# ICEBOX Demo 1: Vulnerability Scanner Governed by ICEBOX
# =============================================================================
# What this demo shows:
#   1. Start the ICEBOX REPL
#   2. Accept the charter (rules of engagement)
#   3. Add a target to scope
#   4. List available modules
#   5. Load the vuln_scanner module and configure it
#   6. Run the scanner against a project through the governance seam
#   7. View the vulnerability evidence produced
#   8. View the audit trail of the governed execution
#
# Narrator script: see comments below (# Narrator: ...)
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT" || exit 1

# Color output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

echo ""
echo -e "${BLUE}══════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  ICEBOX Demo 1: Vulnerability Scanner — Governed by ICEBOX${NC}"
echo -e "${BLUE}══════════════════════════════════════════════════════════════${NC}"
echo ""
# Narrator: "Welcome to ICEBOX. This demo shows how ICEBOX governs an
# autonomous vulnerability scanner. Every module execution passes through
# the governance seam — charter, scope, policy, and audit."
echo -e "${YELLOW}Press ENTER to start the ICEBOX REPL and configure governance...${NC}"
read -r

# =============================================================================
# Step 1: Start the CLI and pipe commands
# =============================================================================
echo ""
echo -e "${GREEN}${BOLD}[1/7] Starting ICEBOX REPL and configuring governance${NC}"
echo ""

# Narrator: "We start by accepting the charter — this is the legal/ethical
# rules of engagement that every module must comply with."
echo -e "  ${CYAN}→${NC} charter accept \"pentest-2026-demo\""
echo -e "  ${CYAN}→${NC} scope add /path/to/project"
echo -e "  ${CYAN}→${NC} list"
echo -e "  ${CYAN}→${NC} use vuln_scanner"
echo -e "  ${CYAN}→${NC} set project_dir $PROJECT_ROOT"
echo ""

echo -e "${YELLOW}Press ENTER to execute governance setup + module load...${NC}"
read -r

printf "charter accept pentest-2026-demo\nscope add %s\nlist\nuse vuln_scanner\nset project_dir %s\ninfo\n" \
    "$PROJECT_ROOT" "$PROJECT_ROOT" | cargo run -p icebox-cli 2>/dev/null

echo ""
echo -e "${YELLOW}Press ENTER to continue to the vulnerability scan...${NC}"
read -r

# =============================================================================
# Step 2: Configure and run the scanner
# =============================================================================
echo ""
echo -e "${GREEN}${BOLD}[2/7] Running vulnerability scanner against the project${NC}"
echo ""

# Narrator: "Now we run the vuln_scanner through the governance seam. ICEBOX
# checks: is the charter accepted? Is the target in scope? Is the risk level
# within limits? Has the operator approved this action?"
echo -e "  ${CYAN}→${NC} Scanning $PROJECT_ROOT dependencies via OSV.dev API..."
echo -e "  ${CYAN}→${NC} This queries OSV.dev for known CVEs per dependency"
echo -e "  ${CYAN}→${NC} then enriches with EPSS exploit-probability scores"
echo ""

echo -e "${YELLOW}Press ENTER to run the vuln_scanner...${NC}"
read -r

printf "use vuln_scanner\nset project_dir %s\nrun --approve %s\nexit\n" \
    "$PROJECT_ROOT" "$PROJECT_ROOT" | cargo run -p icebox-cli 2>/dev/null

echo ""
echo -e "${YELLOW}Press ENTER to view the evidence output...${NC}"
read -r

# =============================================================================
# Step 3: Start fresh and show evidence
# =============================================================================
echo ""
echo -e "${GREEN}${BOLD}[3/7] Viewing vulnerability evidence${NC}"
echo ""

# Narrator: "After the scan, we can inspect the evidence that was produced.
# Each CVE is tagged with CVSS, EPSS, and KEV membership status."
echo -e "  ${CYAN}→${NC} evidence command shows normalized, scored findings"
echo ""

printf "charter accept pentest-2026-demo\nscope add %s\nuse vuln_scanner\nset project_dir %s\nrun --approve %s\nevidence 50\nexit\n" \
    "$PROJECT_ROOT" "$PROJECT_ROOT" "$PROJECT_ROOT" | cargo run -p icebox-cli 2>/dev/null

echo ""
echo -e "${YELLOW}Press ENTER to view the audit trail...${NC}"
read -r

# =============================================================================
# Step 4: Show the audit trail
# =============================================================================
echo ""
echo -e "${GREEN}${BOLD}[4/7] Viewing the audit trail${NC}"
echo ""

# Narrator: "ICEBOX records every policy decision in an append-only audit
# trail. We can see: who (which module), what (which target), and the verdict."
echo -e "  ${CYAN}→${NC} audit trail shows every decision with reason"
echo -e "  ${CYAN}→${NC} Each entry includes: timestamp, module, target, verdict, impact, context"
echo ""

printf "charter accept pentest-2026-demo\nscope add %s\nuse vuln_scanner\nset project_dir %s\nrun --approve %s\naudit 20\nexit\n" \
    "$PROJECT_ROOT" "$PROJECT_ROOT" "$PROJECT_ROOT" | cargo run -p icebox-cli 2>/dev/null

echo ""
echo -e "${YELLOW}Press ENTER to export audit as CSV...${NC}"
read -r

# =============================================================================
# Step 5: Export audit trail
# =============================================================================
echo ""
echo -e "${GREEN}${BOLD}[5/7] Exporting audit trail as CSV${NC}"
echo ""

# Narrator: "Audit data can be exported as JSON or CSV for compliance reporting,
# SIEM ingestion, or evidence of governance during an audit."
echo -e "  ${CYAN}→${NC} audit export --format csv --out /tmp/icebox_audit.csv"
echo ""

printf "charter accept pentest-2026-demo\nscope add %s\nuse vuln_scanner\nset project_dir %s\nrun --approve %s\naudit export --format csv --out /tmp/icebox_audit.csv\nexit\n" \
    "$PROJECT_ROOT" "$PROJECT_ROOT" "$PROJECT_ROOT" | cargo run -p icebox-cli 2>/dev/null

echo ""
echo -e "${GREEN}${BOLD}  CSV exported to /tmp/icebox_audit.csv${NC}"
echo ""

echo -e "${YELLOW}Press ENTER to view the CSV export...${NC}"
read -r

echo ""
echo -e "${GREEN}${BOLD}[6/7] CSV audit export content:${NC}"
echo ""
cat /tmp/icebox_audit.csv 2>/dev/null || echo "(no audit records - run the scan first)"

echo ""
echo -e "${YELLOW}Press ENTER to see the JSON export too...${NC}"
read -r

# =============================================================================
# Step 6: JSON export
# =============================================================================
echo ""
echo -e "${GREEN}${BOLD}[7/7] Exporting audit trail as JSON${NC}"
echo ""

echo -e "  ${CYAN}→${NC} audit export --format json --out /tmp/icebox_audit.json"
echo ""

printf "charter accept pentest-2026-demo\nscope add %s\nuse vuln_scanner\nset project_dir %s\nrun --approve %s\naudit export --format json --out /tmp/icebox_audit.json\nexit\n" \
    "$PROJECT_ROOT" "$PROJECT_ROOT" "$PROJECT_ROOT" | cargo run -p icebox-cli 2>/dev/null

echo ""
echo -e "${GREEN}${BOLD}  JSON exported to /tmp/icebox_audit.json${NC}"
echo ""

python3 -c "
import json
try:
    with open('/tmp/icebox_audit.json') as f:
        data = json.load(f)
    for i, d in enumerate(data[:5]):
        print(f'  [{d.get(\"at\",\"?\")}] {d.get(\"module\",\"?\")} → {d.get(\"target\",\"?\")} : {d.get(\"verdict\",\"?\")}')
except Exception as e:
    print(f'  (no audit records: {e})')
" 2>/dev/null || echo "  (JSON preview not available)"

echo ""
echo -e "${BLUE}══════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  Demo 1 complete. Key takeaways:${NC}"
echo -e "${BLUE}  • Charter + scope gates must pass before any execution${NC}"
echo -e "${BLUE}  • Every execution is audited with full traceability${NC}"
echo -e "${BLUE}  • Evidence is normalized and CVSS/EPSS/KEV-tagged${NC}"
echo -e "${BLUE}  • Audit can be exported as JSON or CSV for compliance${NC}"
echo -e "${BLUE}══════════════════════════════════════════════════════════════${NC}"
echo ""
