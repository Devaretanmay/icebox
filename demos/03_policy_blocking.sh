#!/usr/bin/env bash
# =============================================================================
# ICEBOX Demo 3: Policy Blocking a Dangerous Action
# =============================================================================
# What this demo shows:
#   1. Setting up governance gates (charter + scope)
#   2. Loading a high-impact module (reverse_shell_payload)
#   3. Attempting to run without approval → BLOCKED by policy
#   4. Adding CVSS-aware deny rule → BLOCKED by CVSS threshold
#   5. Adding capability deny rule → BLOCKED by capability
#   6. Inspecting the policy engine decisions
#   7. Viewing the deny reasons in the audit trail
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
echo -e "${BLUE}  ICEBOX Demo 3: Policy Engine — Blocking Dangerous Actions${NC}"
echo -e "${BLUE}══════════════════════════════════════════════════════════════${NC}"
echo ""
# Narrator: "This demo shows how ICEBOX's policy engine blocks dangerous
# actions before they reach a target. We'll demonstrate three types of policy
# gates: max-risk ceiling, CVSS threshold blocking, and capability denial."

echo -e "${YELLOW}Press ENTER to start...${NC}"
read -r

# =============================================================================
# Step 1: Governance setup
# =============================================================================
echo ""
echo -e "${GREEN}${BOLD}[1/7] Setting up governance foundation${NC}"
echo ""

# Narrator: "First, we accept the charter and add targets to scope. Without
# these, the governance seam blocks everything."
echo -e "  ${CYAN}→${NC} charter accept \"policy-demo\""
echo -e "  ${CYAN}→${NC} scope add 10.0.0.0/8"
echo -e "  ${CYAN}→${NC} role --set admin"
echo ""

echo -e "${YELLOW}Press ENTER to set up governance...${NC}"
read -r

printf "charter accept policy-demo\nscope add 10.0.0.0/8\nrole --set admin\nexit\n" \
    | cargo run 2>/dev/null

echo ""
echo -e "${YELLOW}Press ENTER to continue...${NC}"
read -r

# =============================================================================
# Step 2: Load reverse shell and try to run without approval
# =============================================================================
echo ""
echo -e "${GREEN}${BOLD}[2/7] Attempting high-risk action WITHOUT approval${NC}"
echo ""

# Narrator: "We load the reverse_shell_payload module — this generates
# exploit shellcode and one-liners. Without operator approval, the policy
# engine blocks it because the module's impact is Critical and the default
# max-risk is Medium."
echo -e "  ${CYAN}→${NC} use reverse_shell_payload"
echo -e "  ${CYAN}→${NC} set lhost 10.0.0.5"
echo -e "  ${CYAN}→${NC} set lport 4444"
echo -e "  ${CYAN}→${NC} run 10.0.0.5  ${RED}(← WITHOUT --approve)${NC}"
echo ""

echo -e "${YELLOW}Press ENTER to attempt blocked execution...${NC}"
read -r

printf "charter accept policy-demo\nscope add 10.0.0.0/8\nuse reverse_shell_payload\nset lhost 10.0.0.5\nset lport 4444\nrun 10.0.0.5\nexit\n" \
    | cargo run 2>/dev/null

echo ""
echo -e "  ${RED}✗ BLOCKED — The policy engine denied execution because the"
echo -e "     module's impact (Critical) exceeds the max-risk ceiling.${NC}"
echo ""
echo -e "${YELLOW}Press ENTER to continue...${NC}"
read -r

# =============================================================================
# Step 3: Now approve it and let it run
# =============================================================================
echo ""
echo -e "${GREEN}${BOLD}[3/7] Running with operator approval${NC}"
echo ""

# Narrator: "When the operator explicitly approves with --approve, the
# approval gate opens and the module can execute. This is the 'break glass'
# mechanism for legitimate high-risk operations."
echo -e "  ${CYAN}→${NC} run --approve 10.0.0.5  ${GREEN}(← WITH operator approval)${NC}"
echo ""

echo -e "${YELLOW}Press ENTER to run with approval...${NC}"
read -r

printf "charter accept policy-demo\nscope add 10.0.0.0/8\nuse reverse_shell_payload\nset lhost 10.0.0.5\nset lport 4444\nrun --approve 10.0.0.5\nexit\n" \
    | cargo run 2>/dev/null

echo ""
echo -e "  ${GREEN}✓ ALLOWED — Operator approval overrode the max-risk gate.${NC}"
echo ""
echo -e "${YELLOW}Press ENTER to continue...${NC}"
read -r

# =============================================================================
# Step 4: Add CVSS deny rule and show it blocks
# =============================================================================
echo ""
echo -e "${GREEN}${BOLD}[4/7] Adding CVSS-aware deny rule${NC}"
echo ""

# Narrator: "Now we add a DenyIfCvssAbove policy rule. This blocks any module
# whose CVSS score exceeds the threshold — even with operator approval. CVSS
# rules are evaluated independently of the approval gate."
echo -e "  ${CYAN}→${NC} policy rule add deny-cvss 7.5"
echo -e "  ${CYAN}→${NC} policy rules"
echo ""

echo -e "${YELLOW}Press ENTER to add the CVSS deny rule...${NC}"
read -r

printf "charter accept policy-demo\nscope add 10.0.0.0/8\npolicy rule add deny-cvss 7.5\npolicy rules\nexit\n" \
    | cargo run 2>/dev/null

echo ""
echo -e "${YELLOW}Press ENTER to demonstrate CVSS-based blocking...${NC}"
read -r

# Now test with a module that simulates CVSS scoring
echo ""
echo -e "${GREEN}${BOLD}[5/7] Running vuln_scanner with CVSS policy active${NC}"
echo ""

# Narrator: "When we run the vuln_scanner with the DenyIfCvssAbove rule active,
# modules that produce evidence with CVSS > 7.5 will be blocked. The policy
# engine evaluates the combined CVSS score of all findings."
echo -e "  ${CYAN}→${NC} use vuln_scanner"
echo -e "  ${CYAN}→${NC} set project_dir $PROJECT_ROOT"
echo -e "  ${CYAN}→${NC} run --approve $PROJECT_ROOT"
echo ""

echo -e "${YELLOW}Press ENTER to test CVSS policy gate...${NC}"
read -r

printf "charter accept policy-demo\nscope add %s\npolicy rule add deny-cvss 7.5\nuse vuln_scanner\nset project_dir %s\nrun --approve %s\nexit\n" \
    "$PROJECT_ROOT" "$PROJECT_ROOT" "$PROJECT_ROOT" | cargo run 2>/dev/null

echo ""
echo -e "${YELLOW}Press ENTER to continue...${NC}"
read -r

# =============================================================================
# Step 5: Add capability deny rule
# =============================================================================
echo ""
echo -e "${GREEN}${BOLD}[6/7] Adding capability-based deny rule${NC}"
echo ""

# Narrator: "ICEBOX also supports capability-based policy rules. We can deny
# specific capabilities like credential_access or persistence across all
# modules, regardless of risk level or approval status."
echo -e "  ${CYAN}→${NC} policy rule add deny persistence"
echo -e "  ${CYAN}→${NC} policy rules"
echo ""

echo -e "${YELLOW}Press ENTER to add the capability deny rule...${NC}"
read -r

printf "charter accept policy-demo\nscope add 10.0.0.0/8\npolicy rule add deny persistence\npolicy rules\nexit\n" \
    | cargo run 2>/dev/null

echo ""
echo -e "${YELLOW}Press ENTER to inspect all policy rules...${NC}"
read -r

# =============================================================================
# Step 6: View all policy rules and inspect deny reasons
# =============================================================================
echo ""
echo -e "${GREEN}${BOLD}[7/7] Inspecting audit trail — viewing deny reasons${NC}"
echo ""

# Narrator: "Every policy decision — whether Allow or Deny — is recorded in
# the audit trail with the reason. Let's view what got blocked and why.
# The audit shows us the exact policy rule that triggered each denial."
echo -e "  ${CYAN}→${NC} audit 50"
echo -e "  ${CYAN}→${NC} Deny entries show the reason (which rule triggered)"
echo ""

echo -e "${YELLOW}Press ENTER to view the audit trail...${NC}"
read -r

printf "charter accept policy-demo\nscope add %s\npolicy rule add deny-cvss 7.5\nuse reverse_shell_payload\nset lhost 10.0.0.5\nset lport 4444\nrun 10.0.0.5\nrun --approve 10.0.0.5\naudit 50\nexit\n" \
    "$PROJECT_ROOT" | cargo run 2>/dev/null

echo ""
echo -e "${BLUE}══════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  Demo 3 complete. Key takeaways:${NC}"
echo -e "${BLUE}  • Without approval: high-risk actions BLOCKED by max-risk gate${NC}"
echo -e "${BLUE}  • With --approve: operator can override max-risk ceiling${NC}"
echo -e "${BLUE}  • DenyIfCvssAbove: blocks based on CVSS score threshold${NC}"
echo -e "${BLUE}  • Capability deny: blocks specific capabilities globally${NC}"
echo -e "${BLUE}  • Every decision is audited with a human-readable reason${NC}"
echo -e "${BLUE}  • Deny ALWAYS wins — even over operator approval${NC}"
echo -e "${BLUE}══════════════════════════════════════════════════════════════${NC}"
echo ""
