#!/usr/bin/env bash
# =============================================================================
# ICEBOX Demo 5: Approval Workflow — Request → List → Approve → Execute
# =============================================================================
# What this demo shows:
#   1. Setting up governance with RequireApprovalIf policy
#   2. Creating an approval request for a dangerous module
#   3. Listing pending approval requests
#   4. Approving the request — triggers automatic execution
#   5. Denying a request — blocks execution
#   6. Viewing the approval decisions in the audit trail
#   7. Approval queue management (bulk operations)
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
RED='\033[0;31m'
NC='\033[0m'
BOLD='\033[1m'

echo ""
echo -e "${BLUE}══════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  ICEBOX Demo 5: Approval Workflow — Request → Approve → Execute${NC}"
echo -e "${BLUE}══════════════════════════════════════════════════════════════${NC}"
echo ""
# Narrator: "This demo shows ICEBOX's approval workflow. When a module requires
# approval (e.g., due to CVSS threshold, capability, or target pattern), the
# operator can review, approve, or deny the request — with full audit trail."

echo -e "${YELLOW}Press ENTER to start...${NC}"
read -r

# =============================================================================
# Step 1: Governance setup
# =============================================================================
echo ""
echo -e "${GREEN}${BOLD}[1/8] Setting up governance with approval-aware policy${NC}"
echo ""

# Narrator: "We configure the governance layer: accept charter, set scope,
# add a RequireApprovalIf rule that gates on CVSS > 5.0 or KEV membership."
echo -e "  ${CYAN}→${NC} charter accept \"approval-demo\""
echo -e "  ${CYAN}→${NC} scope add 10.0.0.0/8"
echo -e "  ${CYAN}→${NC} role --set admin"
echo -e "  ${CYAN}→${NC} policy rule add deny-cvss 9.0  ${YELLOW}(block critical outright)${NC}"
echo -e "  ${CYAN}→${NC} policy rules"
echo ""

echo -e "${YELLOW}Press ENTER to set up governance...${NC}"
read -r

printf "charter accept approval-demo\nscope add 10.0.0.0/8\nrole --set admin\npolicy rule add deny-cvss 9.0\npolicy rules\nexit\n" \
    | cargo run 2>/dev/null

echo ""
echo -e "${YELLOW}Press ENTER to continue...${NC}"
read -r

# =============================================================================
# Step 2: Create an approval request via the REST API (simulated)
# =============================================================================
echo ""
echo -e "${GREEN}${BOLD}[2/8] Creating an approval request${NC}"
echo ""

# Narrator: "The approval workflow starts when a module needs approval. This
# can be triggered automatically by policy rules (RequireApprovalIf) or
# manually by an operator. Let's create an approval request for the
# reverse_shell_payload module against a target."
echo -e "  ${CYAN}→${NC} approve request reverse_shell_payload 10.0.0.5 \\"
echo -e "  ${CYAN}      ${NC} --reason \"Need reverse shell for post-exploitation validation\" \\"
echo -e "  ${CYAN}      ${NC} --set lhost 10.0.0.5 --set lport 4444"
echo ""

echo -e "${YELLOW}Press ENTER to create the approval request...${NC}"
read -r

printf "charter accept approval-demo\nscope add 10.0.0.0/8\napprove request reverse_shell_payload 10.0.0.5 --reason \"Need reverse shell for post-exploitation validation\" --set lhost 10.0.0.5 --set lport 4444\nexit\n" \
    | cargo run 2>/dev/null

echo ""
echo -e "  ${GREEN}✓ Approval request created.${NC}"
echo ""
echo -e "${YELLOW}Press ENTER to continue...${NC}"
read -r

# =============================================================================
# Step 3: List pending approval requests
# =============================================================================
echo ""
echo -e "${GREEN}${BOLD}[3/8] Listing pending approval requests${NC}"
echo ""

# Narrator: "Operators can list all pending approval requests to see what's
# waiting for review. Each request shows: ID, module, target, status, and reason."
echo -e "  ${CYAN}→${NC} approve list"
echo ""

echo -e "${YELLOW}Press ENTER to list pending requests...${NC}"
read -r

printf "charter accept approval-demo\nscope add 10.0.0.0/8\napprove request reverse_shell_payload 10.0.0.5 --reason \"Need reverse shell for post-exploitation\" --set lhost 10.0.0.5 --set lport 4444\napprove list\nexit\n" \
    | cargo run 2>/dev/null

echo ""
echo -e "${YELLOW}Press ENTER to continue...${NC}"
read -r

# =============================================================================
# Step 4: Approve the request — automatic execution
# =============================================================================
echo ""
echo -e "${GREEN}${BOLD}[4/8] Approving the request — triggers automatic execution${NC}"
echo ""

# Narrator: "When an operator approves a request, ICEBOX automatically
# executes the module with the specified options. The execution goes through
# the governance seam — charter, scope, policy, and audit — just like any
# other execution. Approval is recorded in the audit trail."
echo -e "  ${CYAN}→${NC} approve approve 1"
echo ""

echo -e "${YELLOW}Press ENTER to approve and execute...${NC}"
read -r

printf "charter accept approval-demo\nscope add 10.0.0.0/8\napprove request reverse_shell_payload 10.0.0.5 --reason \"Need reverse shell for post-exploitation\" --set lhost 10.0.0.5 --set lport 4444\napprove approve 1\nexit\n" \
    | cargo run 2>/dev/null

echo ""
echo -e "  ${GREEN}✓ Request approved and module executed.${NC}"
echo ""
echo -e "${YELLOW}Press ENTER to continue...${NC}"
read -r

# =============================================================================
# Step 5: Create another request and deny it
# =============================================================================
echo ""
echo -e "${GREEN}${BOLD}[5/8] Creating a second request and denying it${NC}"
echo ""

# Narrator: "Not all requests should be approved. Let's create another request
# and this time deny it to show the deny workflow."
echo -e "  ${CYAN}→${NC} approve request tcp_port_scanner 10.0.0.99 \\"
echo -e "  ${CYAN}      ${NC} --reason \"Unauthorized target — should be denied\" \\"
echo -e "  ${CYAN}      ${NC} --set host 10.0.0.99 --set ports 22,80,443"
echo ""

echo -e "${YELLOW}Press ENTER to create the second request...${NC}"
read -r

printf "charter accept approval-demo\nscope add 10.0.0.0/8\napprove request tcp_port_scanner 10.0.0.99 --reason \"Unauthorized target — should be denied\" --set host 10.0.0.99 --set ports 22,80,443\napprove list\nexit\n" \
    | cargo run 2>/dev/null

echo ""
echo -e "${YELLOW}Press ENTER to deny the request...${NC}"
read -r

echo ""
echo -e "  ${CYAN}→${NC} approve deny 2"
echo ""

printf "charter accept approval-demo\nscope add 10.0.0.0/8\napprove request tcp_port_scanner 10.0.0.99 --reason \"Unauthorized target — should be denied\" --set host 10.0.0.99 --set ports 22,80,443\napprove deny 2\nexit\n" \
    | cargo run 2>/dev/null

echo ""
echo -e "  ${RED}✗ Request #2 denied — execution blocked.${NC}"
echo ""
echo -e "${YELLOW}Press ENTER to continue...${NC}"
read -r

# =============================================================================
# Step 6: View the full audit trail with approval decisions
# =============================================================================
echo ""
echo -e "${GREEN}${BOLD}[6/8] Viewing audit trail with approval decisions${NC}"
echo ""

# Narrator: "Every approval and denial is recorded in the audit trail alongside
# policy decisions. This provides a complete chronological record of who
# approved what, when, and why."
echo -e "  ${CYAN}→${NC} audit 50"
echo ""

echo -e "${YELLOW}Press ENTER to view the audit trail...${NC}"
read -r

printf "charter accept approval-demo\nscope add 10.0.0.0/8\napprove request reverse_shell_payload 10.0.0.5 --reason \"Need reverse shell\" --set lhost 10.0.0.5 --set lport 4444\napprove approve 1\napprove request tcp_port_scanner 10.0.0.99 --reason \"Unauthorized target\" --set host 10.0.0.99 --set ports 22,80,443\napprove deny 2\naudit 50\nexit\n" \
    | cargo run 2>/dev/null

echo ""
echo -e "${YELLOW}Press ENTER to continue...${NC}"
read -r

# =============================================================================
# Step 7: View evidence from the approved execution
# =============================================================================
echo ""
echo -e "${GREEN}${BOLD}[7/8] Viewing evidence from approved execution${NC}"
echo ""

# Narrator: "After approval and execution, we can inspect the evidence that
# was produced. This shows what the module actually did — exactly what was
# authorized."
echo -e "  ${CYAN}→${NC} evidence 20"
echo ""

echo -e "${YELLOW}Press ENTER to view evidence...${NC}"
read -r

printf "charter accept approval-demo\nscope add 10.0.0.0/8\napprove request reverse_shell_payload 10.0.0.5 --reason \"Need reverse shell\" --set lhost 10.0.0.5 --set lport 4444\napprove approve 1\nevidence 20\nexit\n" \
    | cargo run 2>/dev/null

echo ""
echo -e "${YELLOW}Press ENTER to continue...${NC}"
read -r

# =============================================================================
# Step 8: Export approval audit trail
# =============================================================================
echo ""
echo -e "${GREEN}${BOLD}[8/8] Exporting approval audit for compliance${NC}"
echo ""

# Narrator: "All approval workflow artifacts can be exported for compliance
# and auditing purposes. The CSV export includes each decision with timestamps
# and reasons — ready for SIEM ingestion or compliance review."
echo -e "  ${CYAN}→${NC} audit export --format csv --out /tmp/icebox_approval_audit.csv"
echo -e "  ${CYAN}→${NC} audit export --format json --out /tmp/icebox_approval_audit.json"
echo ""

echo -e "${YELLOW}Press ENTER to export...${NC}"
read -r

printf "charter accept approval-demo\nscope add 10.0.0.0/8\napprove request reverse_shell_payload 10.0.0.5 --reason \"Need reverse shell\" --set lhost 10.0.0.5 --set lport 4444\napprove approve 1\naudit export --format csv --out /tmp/icebox_approval_audit.csv\naudit export --format json --out /tmp/icebox_approval_audit.json\nexit\n" \
    | cargo run 2>/dev/null

echo -e "${GREEN}${BOLD}  Approval audit exported:${NC}"
echo -e "  • /tmp/icebox_approval_audit.csv"
echo -e "  • /tmp/icebox_approval_audit.json"
echo ""

echo -e "${BLUE}══════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  Demo 5 complete. Key takeaways:${NC}"
echo -e "${BLUE}  • Approval requests capture module + target + options${NC}"
echo -e "${BLUE}  • Approving a request triggers automatic execution${NC}"
echo -e "${BLUE}  • Denying a request blocks execution with audit record${NC}"
echo -e "${BLUE}  • All approval decisions are in the audit trail${NC}"
echo -e "${BLUE}  • Evidence shows exactly what the approved module did${NC}"
echo -e "${BLUE}  • Full compliance export: JSON and CSV formats${NC}"
echo -e "${BLUE}══════════════════════════════════════════════════════════════${NC}"
echo ""
