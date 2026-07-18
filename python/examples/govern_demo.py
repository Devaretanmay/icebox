"""Govern a task via the flagship `govern()` API (mirrors Rust and REST)."""

from icebox import govern, Governance

with govern() as g:
    verdict = g.preflight({
        "action": "scan",
        "target": "10.0.0.5",
        "capability": "network_scan",
        "impact": "low",
        "destructive": False,
    })
    print("preflight:", verdict)
    if verdict.get("approved"):
        outcome = {"success": True, "evidence": ["port 22 open"], "data": {}}
        print("complete:", g.complete(outcome, verdict.get("decision", "allow")))

gov = Governance({
    "charter": {"accepted": True, "engagement": "demo", "rules_of_engagement": []},
    "scope": {"allow": ["10.0.0.0/24"]},
    "max_risk": "critical",
    "role": "admin",
})

result = gov.run({
    "name": "scan",
    "target": "10.0.0.5",
    "capabilities": ["network_scan"],
    "impact": "low",
    "destructive": False,
})
print("in-process run:", result)
