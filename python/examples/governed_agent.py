"""End-to-end example: govern a Python agent through the ICEBOX C ABI.

Run after building the C ABI:

    cargo build
    cd python && python examples/governed_agent.py
"""

import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from icebox import Governance


def main():
    config = {
        "charter": {
            "accepted": True,
            "engagement": "demo",
            "rules_of_engagement": ["no destruction of production"],
        },
        "scope": {"allow": ["10.0.0.0/8"]},
        "max_risk": "critical",
        "role": "admin",
        "policy_set": {
            "rules": [{"deny_capability": "persistence"}],
            "version": 1,
        },
        "rate_limits": {},
    }

    gov = Governance(config)

    # low-risk, in-scope scan is allowed
    scan = {
        "name": "scan",
        "target": "10.0.0.5",
        "capabilities": ["network_scan"],
        "impact": "low",
        "destructive": False,
        "context": "autonomous",
    }
    print("scan verdict:", gov.check(scan))

    # persistence attempt is hard-denied by policy
    implant = {
        "name": "implant",
        "target": "10.0.0.9",
        "capabilities": ["persistence"],
        "impact": "high",
        "destructive": False,
        "context": "autonomous",
    }
    print("implant verdict:", gov.check(implant))

    # destructive, high-risk task is gated on approval (supervised)
    wipe = {
        "name": "wipe",
        "target": "10.0.0.7",
        "capabilities": ["filesystem_modification"],
        "impact": "high",
        "destructive": True,
        "context": "autonomous",
    }
    verdict = gov.check(wipe)
    print("wipe verdict:", verdict)
    needs = verdict.get("NeedsApproval")
    if needs:
        approved = gov.approve(needs["approval_id"])
        print(f"approved wipe? {approved}; pending now: {gov.pending()}")

    # out-of-scope is blocked
    off_scope = dict(scan, target="8.8.8.8")
    print("off-scope verdict:", gov.check(off_scope))

    # full audit trail
    print("audit json:")
    print(json.dumps(gov.audit_json(), indent=2))


if __name__ == "__main__":
    main()
