#!/usr/bin/env bash
# =============================================================================
# ICEBOX Demo 2: Multi-Agent Campaign Through the Orchestrator
# =============================================================================
# What this demo shows:
#   1. Setting up governance for a multi-agent campaign
#   2. Running multiple concurrent agents through the Orchestrator
#   3. Each agent funnels through the same governance seam
#   4. Aggregate audit trail across all agents
#   5. Viewing the combined campaign report
#
# NOTE: This demo requires Ollama running locally with the llama3.2 model.
#       If Ollama is not available, the demo shows the orchestration setup
#       and a summary of how multi-agent governance works.
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
echo -e "${BLUE}  ICEBOX Demo 2: Multi-Agent Campaign — Orchestrated Governance${NC}"
echo -e "${BLUE}══════════════════════════════════════════════════════════════${NC}"
echo ""
# Narrator: "This demo shows ICEBOX's multi-agent orchestration. Multiple
# autonomous agents run concurrently against different targets, but every
# single action from every agent funnels through the same governance seam."
echo ""

# Check for Ollama
if command -v ollama &>/dev/null; then
    OLLAMA_AVAILABLE=true
    echo -e "${GREEN}✓ Ollama detected${NC}"
else
    OLLAMA_AVAILABLE=false
    echo -e "${YELLOW}⚠ Ollama not found — showing orchestration setup only${NC}"
    echo -e "${YELLOW}  Install Ollama (https://ollama.ai) and pull llama3.2 for${NC}"
    echo -e "${YELLOW}  the full agent demo.${NC}"
fi

echo ""
echo -e "${YELLOW}Press ENTER to start...${NC}"
read -r

# =============================================================================
# Step 1: Governance setup
# =============================================================================
echo ""
echo -e "${GREEN}${BOLD}[1/6] Setting up governance for multi-agent campaign${NC}"
echo ""

# Narrator: "First, we configure the governance layer. The charter defines our
# rules of engagement, and the scope lists authorized targets."
echo -e "  ${CYAN}→${NC} charter accept \"multi-agent-pentest\""
echo -e "  ${CYAN}→${NC} scope add 10.0.0.0/8"
echo -e "  ${CYAN}→${NC} scope add 192.168.1.0/24"
echo ""

echo -e "${YELLOW}Press ENTER to set up governance...${NC}"
read -r

printf "charter accept multi-agent-pentest\nscope add 10.0.0.0/8\nscope add 192.168.1.0/24\nrole --set admin\nexit\n" \
    | cargo run -p icebox-cli 2>/dev/null

echo ""
echo -e "${YELLOW}Press ENTER to continue...${NC}"
read -r

# =============================================================================
# Step 2: Configure CVSS-aware policy
# =============================================================================
echo ""
echo -e "${GREEN}${BOLD}[2/6] Adding CVSS-aware policy rules for the campaign${NC}"
echo ""

# Narrator: "We add policy rules that govern what each agent is allowed to do.
# Here we block any agent from attempting exploitation of vulnerabilities with
# CVSS > 7.0, and we require approval for any persistence capability."
echo -e "  ${CYAN}→${NC} policy rule add deny-cvss 7.0"
echo -e "  ${CYAN}→${NC} policy rule add deny credential_access"
echo -e "  ${CYAN}→${NC} policy rule add maxrisk high"
echo ""

printf "charter accept multi-agent-pentest\nscope add 10.0.0.0/8\npolicy rule add deny-cvss 7.0\npolicy rule add deny credential_access\npolicy rule add maxrisk high\npolicy rules\nexit\n" \
    | cargo run -p icebox-cli 2>/dev/null

echo ""
echo -e "${YELLOW}Press ENTER to continue to the campaign...${NC}"
read -r

# =============================================================================
# Step 3: Run the multi-agent campaign
# =============================================================================
echo ""
echo -e "${GREEN}${BOLD}[3/6] Running multi-agent campaign${NC}"
echo ""

# Narrator: "Now we launch the campaign. The Orchestrator spawns one agent per
# target. Each agent independently plans its approach — but every module
# execution must pass through the governance seam."
echo -e "  ${CYAN}→${NC} campaign 10.0.0.5 192.168.1.100 approve"
echo -e "  ${CYAN}→${NC}   (2 targets, pre-approved by operator)"
echo ""

if [ "$OLLAMA_AVAILABLE" = true ]; then
    echo -e "${YELLOW}Press ENTER to run the multi-agent campaign (requires Ollama)...${NC}"
    read -r

    printf "charter accept multi-agent-pentest\nscope add 10.0.0.0/8\nscope add 192.168.1.0/24\ncampaign 10.0.0.5 192.168.1.100 approve\nexit\n" \
        | cargo run -p icebox-cli 2>/dev/null
else
    echo -e "${YELLOW}  (Ollama not available — showing campaign structure)${NC}"
    echo ""
    echo -e "  The campaign command would invoke:"
    echo -e "  ${CYAN}  →${NC} Orchestrator::run([\"10.0.0.5\", \"192.168.1.100\"], LlmPlanner)"
    echo -e "  ${CYAN}  →${NC} Agent 1 (target: 10.0.0.5): builds plan via LLM"
    echo -e "  ${CYAN}  →${NC} Agent 2 (target: 192.168.1.100): builds plan via LLM"
    echo -e "  ${CYAN}  →${NC} Each module execution → ModuleExecutor::execute() seam"
    echo -e "  ${CYAN}  →${NC} All decisions recorded in shared audit trail"
    echo ""
    echo -e "${YELLOW}Press ENTER to continue...${NC}"
    read -r
fi

# =============================================================================
# Step 4: View the aggregate audit trail
# =============================================================================
echo ""
echo -e "${GREEN}${BOLD}[4/6] Viewing aggregate audit trail${NC}"
echo ""

# Narrator: "Because all agents funnel through the same seam, the audit trail
# contains every decision from every agent. We can see which agent did what,
# when, and whether it was allowed or blocked."
echo -e "  ${CYAN}→${NC} audit shows decisions from all concurrent agents"
echo ""

if [ "$OLLAMA_AVAILABLE" = true ]; then
    printf "charter accept multi-agent-pentest\nscope add 10.0.0.0/8\ncampaign 10.0.0.5 192.168.1.100 approve\naudit 50\nexit\n" \
        | cargo run -p icebox-cli 2>/dev/null
else
    echo -e "${YELLOW}  (Simulated audit output)${NC}"
    echo ""
    echo -e "  [2026-07-15T10:00:01] tcp_port_scanner → 10.0.0.5 : allow (impact=medium, ctx=Cli)"
    echo -e "  [2026-07-15T10:00:02] tcp_port_scanner → 192.168.1.100 : allow (impact=medium, ctx=Cli)"
    echo -e "  [2026-07-15T10:00:03] http_probe → 10.0.0.5 : allow (impact=low, ctx=Cli)"
    echo -e "  [2026-07-15T10:00:04] http_probe → 192.168.1.100 : allow (impact=low, ctx=Cli)"
    echo -e "  [2026-07-15T10:00:05] reverse_shell_payload → 10.0.0.5 : deny (impact=critical, ctx=Cli)"
    echo -e "  [2026-07-15T10:00:06] reverse_shell_payload → 192.168.1.100 : deny (impact=critical, ctx=Cli)"
    echo ""
    echo -e "  ${YELLOW}Note the last two: reverse_shell_payload was BLOCKED because"
    echo -e "  its impact (critical) exceeds our maxrisk policy (high).${NC}"
    echo ""
    echo -e "${YELLOW}Press ENTER to continue...${NC}"
    read -r
fi

# =============================================================================
# Step 5: View reasoning traces
# =============================================================================
echo ""
echo -e "${GREEN}${BOLD}[5/6] Viewing agent reasoning traces${NC}"
echo ""

# Narrator: "ICEBOX captures reasoning traces from the autonomous agents.
# These explain why the agent chose each action, providing full explainability
# for human operators and compliance auditors."
echo -e "  ${CYAN}→${NC} traces shows each agent's decision reasoning"
echo -e "  ${CYAN}→${NC} Each trace includes: phase, context, summary, and actions taken"
echo ""

if [ "$OLLAMA_AVAILABLE" = true ]; then
    printf "charter accept multi-agent-pentest\nscope add 10.0.0.0/8\ncampaign 10.0.0.5 192.168.1.100 approve\ntraces 20\nexit\n" \
        | cargo run -p icebox-cli 2>/dev/null
else
    echo -e "${YELLOW}  (Simulated traces output)${NC}"
    echo ""
    echo -e "  [2026-07-15T10:00:00] phase=recon ctx=512 : Port scan 10.0.0.5 | actions=[tcp_port_scanner]"
    echo -e "  [2026-07-15T10:00:01] phase=recon ctx=512 : Port scan 192.168.1.100 | actions=[tcp_port_scanner]"
    echo -e "  [2026-07-15T10:00:02] phase=fingerprint ctx=768 : HTTP banner grab | actions=[http_probe]"
    echo -e "  [2026-07-15T10:00:03] phase=exploit ctx=1024 : Attempt reverse shell → BLOCKED by policy | actions=[reverse_shell_payload]"
    echo ""
    echo -e "${YELLOW}Press ENTER to continue...${NC}"
    read -r
fi

# =============================================================================
# Step 6: Export campaign compliance report
# =============================================================================
echo ""
echo -e "${GREEN}${BOLD}[6/6] Exporting campaign compliance report${NC}"
echo ""

# Narrator: "At the end of a campaign, you can export all governance artifacts:
# audit trail as CSV for SIEM, structured JSON for compliance, and evidence
# for each finding. This proves what was done, by whom, and whether governance
# actually held."
echo -e "  ${CYAN}→${NC} audit export --format csv --out /tmp/icebox_campaign_audit.csv"
echo -e "  ${CYAN}→${NC} audit export --format json --out /tmp/icebox_campaign_audit.json"
echo ""

printf "charter accept multi-agent-pentest\nscope add 10.0.0.0/8\naudit export --format csv --out /tmp/icebox_campaign_audit.csv\naudit export --format json --out /tmp/icebox_campaign_audit.json\nexit\n" \
    | cargo run -p icebox-cli 2>/dev/null

echo -e "${GREEN}${BOLD}  Compliance artifacts exported:${NC}"
echo -e "  • /tmp/icebox_campaign_audit.csv"
echo -e "  • /tmp/icebox_campaign_audit.json"
echo ""

echo -e "${BLUE}══════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  Demo 2 complete. Key takeaways:${NC}"
echo -e "${BLUE}  • Multi-agent campaigns share one governed audit trail${NC}"
echo -e "${BLUE}  • Every agent action funnels through the execution seam${NC}"
echo -e "${BLUE}  • Policy rules apply uniformly across all agents${NC}"
echo -e "${BLUE}  • Reasoning traces provide explainability for operators${NC}"
echo -e "${BLUE}  • Compliance artifacts export as JSON or CSV${NC}"
echo -e "${BLUE}══════════════════════════════════════════════════════════════${NC}"
echo ""
