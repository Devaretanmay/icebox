#!/usr/bin/env bash
# =============================================================================
# ICEBOX Demo 4: Continuous Validation — Detecting Policy Drift
# =============================================================================
# What this demo shows:
#   1. Running a validation campaign and saving the report
#   2. Changing the policy rules (adding a deny rule)
#   3. Running validation again and saving the second report
#   4. Diffing the two reports to detect policy drift
#   5. Viewing the policy version changes
#   6. Interpreting the diff: evidence delta, decisions delta, traces delta
#
# NOTE: This demo requires Ollama for the full `validate run` command.
#       If Ollama is not available, the demo shows policy version tracking
#       and workspace snapshot comparison instead.
#
# Narrator script: see comments below (# Narrator: ...)
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT" || exit 1

# Guard: ensure we're in the ICEBOX project
if [ ! -f Cargo.toml ]; then
    echo "ERROR: Cargo.toml not found. Run this script from the ICEBOX project root."
    exit 1
fi

# Color output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RED='\033[0;31m'
MAGENTA='\033[0;35m'
NC='\033[0m'
BOLD='\033[1m'

echo ""
echo -e "${BLUE}══════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  ICEBOX Demo 4: Continuous Validation — Detecting Policy Drift${NC}"
echo -e "${BLUE}══════════════════════════════════════════════════════════════${NC}"
echo ""
# Narrator: "This demo shows ICEBOX's continuous validation capability. As
# policies evolve over time, ICEBOX tracks every change via a monotonic policy
# version and can diff any two states to detect drift."

# Check for Ollama
if command -v ollama &>/dev/null; then
    OLLAMA_AVAILABLE=true
    echo -e "${GREEN}✓ Ollama detected — full validation demo available${NC}"
else
    OLLAMA_AVAILABLE=false
    echo -e "${YELLOW}⚠ Ollama not found — showing policy version tracking,${NC}"
    echo -e "${YELLOW}  workspace snapshots, and drift detection concepts${NC}"
fi

echo ""
echo -e "${YELLOW}Press ENTER to start...${NC}"
read -r

# =============================================================================
# Step 1: Set up governance and show initial policy state
# =============================================================================
echo ""
echo -e "${GREEN}${BOLD}[1/6] Setting up baseline governance state${NC}"
echo ""

# Narrator: "We start by configuring the baseline governance: charter, scope,
# and initial policy rules. The policy version starts at 0 and increments with
# every rule change."
echo -e "  ${CYAN}→${NC} role --set admin"
echo -e "  ${CYAN}→${NC} charter accept validation-demo"
echo -e "  ${CYAN}→${NC} scope add 10.0.0.0/8"
echo -e "  ${CYAN}→${NC} policy rules  ${YELLOW}(version should be 0)${NC}"
echo ""

echo -e "${YELLOW}Press ENTER to set up baseline...${NC}"
read -r

printf "charter accept validation-demo\nscope add 10.0.0.0/8\nrole --set admin\npolicy rules\nexit\n" \
    | cargo run -p icebox-cli 2>/dev/null

echo ""
echo -e "${YELLOW}Press ENTER to continue...${NC}"
read -r

# =============================================================================
# Step 2: Add policy rules and watch version increment
# =============================================================================
echo ""
echo -e "${GREEN}${BOLD}[2/6] Adding policy rules — version increments${NC}"
echo ""

# Narrator: "Every policy mutation bumps the version number monotonically.
# We add a maxrisk rule and a deny-cvss rule, watching the version increment."
echo -e "  ${CYAN}→${NC} policy rule add maxrisk high"
echo -e "  ${CYAN}→${NC} policy rule add deny-cvss 7.0"
echo -e "  ${CYAN}→${NC} policy rules  ${YELLOW}(version should now be 2)${NC}"
echo ""

echo -e "${YELLOW}Press ENTER to add rules...${NC}"
read -r

printf "charter accept validation-demo\nscope add 10.0.0.0/8\npolicy rule add maxrisk high\npolicy rule add deny-cvss 7.0\npolicy rules\nexit\n" \
    | cargo run -p icebox-cli 2>/dev/null

echo ""
echo -e "${YELLOW}Press ENTER to continue...${NC}"
read -r

# =============================================================================
# Step 3: Save workspace snapshot A
# =============================================================================
echo ""
echo -e "${GREEN}${BOLD}[3/6] Saving workspace snapshot (baseline)${NC}"
echo ""

# Narrator: "ICEBOX can save and load workspace snapshots — complete state
# including charter, scope, policy rules, audit trail, and evidence."
echo -e "  ${CYAN}→${NC} save /tmp/icebox_baseline.json"
echo ""

echo -e "${YELLOW}Press ENTER to save snapshot...${NC}"
read -r

printf "charter accept validation-demo\nscope add 10.0.0.0/8\npolicy rule add maxrisk high\npolicy rule add deny-cvss 7.0\nsave /tmp/icebox_baseline.json\nexit\n" \
    | cargo run -p icebox-cli 2>/dev/null

echo ""
echo -e "${GREEN}${BOLD}  Baseline snapshot saved to /tmp/icebox_baseline.json${NC}"
echo ""

echo -e "${YELLOW}Press ENTER to inspect the snapshot...${NC}"
read -r

# Show the snapshot structure via a temp script
cat > /tmp/_icebox_show_snapshot.py << 'SCRIPT'
import json
try:
    with open('/tmp/icebox_baseline.json') as f:
        data = json.load(f)
    print('  Snapshot contains:')
    for key in data.keys():
        val = data[key]
        if isinstance(val, list):
            print(f'    * {key}: {len(val)} items')
        elif isinstance(val, dict):
            print(f'    * {key}: {len(val)} keys')
        else:
            print(f'    * {key}: {val}')
except Exception as e:
    print(f'  (Snapshot not available: {e})')
SCRIPT
python3 /tmp/_icebox_show_snapshot.py 2>/dev/null
rm -f /tmp/_icebox_show_snapshot.py

echo ""
echo -e "${YELLOW}Press ENTER to continue...${NC}"
read -r

# =============================================================================
# Step 4: Modify policy and save snapshot B
# =============================================================================
echo ""
echo -e "${GREEN}${BOLD}[4/6] Modifying policy — saving second snapshot${NC}"
echo ""

# Narrator: "Now we simulate policy drift by changing the rules. We remove
# the maxrisk rule and add a credential_access deny."
echo -e "  ${CYAN}→${NC} policy rule remove 0  ${YELLOW}(removes maxrisk high)${NC}"
echo -e "  ${CYAN}→${NC} policy rule add deny credential_access"
echo -e "  ${CYAN}→${NC} policy rules"
echo -e "  ${CYAN}→${NC} save /tmp/icebox_modified.json"
echo ""

echo -e "${YELLOW}Press ENTER to modify policy and save...${NC}"
read -r

printf "charter accept validation-demo\nscope add 10.0.0.0/8\npolicy rule add maxrisk high\npolicy rule add deny-cvss 7.0\npolicy rule remove 0\npolicy rule add deny credential_access\npolicy rules\nsave /tmp/icebox_modified.json\nexit\n" \
    | cargo run -p icebox-cli 2>/dev/null

echo ""
echo -e "${GREEN}${BOLD}  Modified snapshot saved to /tmp/icebox_modified.json${NC}"
echo ""

echo -e "${YELLOW}Press ENTER to compare policy versions...${NC}"
read -r

# =============================================================================
# Step 5: Diff snapshots or compare policy states
# =============================================================================
echo ""
echo -e "${GREEN}${BOLD}[5/6] Detecting policy drift between snapshots${NC}"
echo ""

# Extract versions using temp scripts
cat > /tmp/_icebox_get_ver.py << 'SCRIPT'
import json, sys
with open(sys.argv[1]) as f:
    data = json.load(f)
print(data.get('policy_set', {}).get('version', '?'))
SCRIPT

BASELINE_VERSION=$(python3 /tmp/_icebox_get_ver.py /tmp/icebox_baseline.json 2>/dev/null || echo "?")
MODIFIED_VERSION=$(python3 /tmp/_icebox_get_ver.py /tmp/icebox_modified.json 2>/dev/null || echo "?")
rm -f /tmp/_icebox_get_ver.py

echo -e "  ${CYAN}→${NC} Baseline policy version: ${BOLD}${BASELINE_VERSION}${NC}"
echo -e "  ${CYAN}→${NC} Modified policy version: ${BOLD}${MODIFIED_VERSION}${NC}"
echo ""

# Show rules via temp script
cat > /tmp/_icebox_show_rules.py << 'SCRIPT'
import json, sys
with open(sys.argv[1]) as f:
    data = json.load(f)
rules = data.get('policy_set', {}).get('rules', [])
for i, r in enumerate(rules):
    print(f'    [{i}] {json.dumps(r)}')
if not rules:
    print('    (no rules)')
SCRIPT

echo -e "  ${MAGENTA}Baseline rules:${NC}"
python3 /tmp/_icebox_show_rules.py /tmp/icebox_baseline.json 2>/dev/null
echo ""
echo -e "  ${MAGENTA}Modified rules:${NC}"
python3 /tmp/_icebox_show_rules.py /tmp/icebox_modified.json 2>/dev/null
rm -f /tmp/_icebox_show_rules.py

echo ""
echo -e "  ${RED}✗ Policy drift detected:${NC}"
echo -e "    • Rule [0] removed: maxrisk high"
echo -e "    • Rule added: deny credential_access"
echo ""

echo -e "${YELLOW}Press ENTER to continue...${NC}"
read -r

# =============================================================================
# Step 6: Run validation diff (or show policy version tracking)
# =============================================================================
echo ""
echo -e "${GREEN}${BOLD}[6/6] Continuous validation — the full drift detection pipeline${NC}"
echo ""

# Narrator: "The validate diff command computes deltas between two validation
# reports: policy version, decisions, evidence, and trace deltas."
echo ""

if [ "$OLLAMA_AVAILABLE" = true ]; then
    echo -e "${YELLOW}Press ENTER to run validation and diff (requires Ollama)...${NC}"
    read -r

    # Run first validation with baseline policy
    echo -e "  ${CYAN}→${NC} validate run --targets 10.0.0.5 --out /tmp/icebox_report_a.json"
    printf "charter accept validation-demo\nscope add 10.0.0.0/8\npolicy rule add maxrisk high\npolicy rule add deny-cvss 7.0\nvalidate run --targets 10.0.0.5 --out /tmp/icebox_report_a.json\nexit\n" \
        | cargo run -p icebox-cli 2>/dev/null

    # Run second validation with modified policy
    echo -e "  ${CYAN}→${NC} validate run --targets 10.0.0.5 --out /tmp/icebox_report_b.json"
    printf "charter accept validation-demo\nscope add 10.0.0.0/8\npolicy rule add maxrisk high\npolicy rule add deny-cvss 7.0\npolicy rule remove 0\npolicy rule add deny credential_access\nvalidate run --targets 10.0.0.5 --out /tmp/icebox_report_b.json\nexit\n" \
        | cargo run -p icebox-cli 2>/dev/null

    # Now diff the two reports
    echo ""
    echo -e "  ${CYAN}→${NC} validate diff /tmp/icebox_report_a.json /tmp/icebox_report_b.json"
    printf "validate diff /tmp/icebox_report_a.json /tmp/icebox_report_b.json\n" \
        | cargo run -p icebox-cli 2>/dev/null

else
    echo -e "${YELLOW}  (Showing drift detection concepts — install Ollama for live demo)${NC}"
    echo ""
    echo -e "  The validate diff command computes:"
    echo ""
    echo -e "  ${CYAN}  policy: 0 -> 3 | jobs +2${NC}"
    echo -e "  ${CYAN}  deltas: evidence +5 decisions +12 traces +3 (targets: 1)${NC}"
    echo ""
    echo -e "  This tells the operator:"
    echo -e "  • Policy version changed from 0 to 3 (3 rule mutations)"
    echo -e "  • 2 more jobs were run in the second campaign"
    echo -e "  • 5 more evidence items, 12 more decisions, 3 more traces"
    echo ""
    echo -e "  ${YELLOW}Policy drift detection enables operators to answer:${NC}"
    echo -e "  • Did the policy change between these two campaigns?"
    echo -e "  • Are agents doing more or less than before?"
    echo -e "  • Is the evidence volume consistent with expectations?"
fi

echo ""
echo -e "${BLUE}══════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  Demo 4 complete. Key takeaways:${NC}"
echo -e "${BLUE}  • Policy version increments monotonically on every mutation${NC}"
echo -e "${BLUE}  • Workspace snapshots preserve full governance state${NC}"
echo -e "${BLUE}  • validate diff computes deltas between two policy states${NC}"
echo -e "${BLUE}  • Drift detection: evidence, decisions, and traces deltas${NC}"
echo -e "${BLUE}  • Continuous validation ensures policy is actually enforced${NC}"
echo -e "${BLUE}══════════════════════════════════════════════════════════════${NC}"
echo ""
