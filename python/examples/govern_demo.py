"""Example: govern a task through ICEBOX using the flagship `govern()` API.

Mirrors the Rust `cargo run --example govern_demo` and the REST
`POST /govern` contract — one mental model across all three surfaces.

Requires a running ICEBOX daemon (`./target/release/icebox-daemon --api`):

    python examples/govern_demo.py
"""

from icebox import govern, Governance


# 1. The flagship single call — a governed session over HTTP.
#    `preflight` runs the action through the full GEE lifecycle; `complete`
#    records the outcome into the tamper-evident audit chain.
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
        # ... actually run your tool here ...
        outcome = {"success": True, "evidence": ["port 22 open"], "data": {}}
        print("complete:", g.complete(outcome, verdict.get("decision", "allow")))


# 2. In-process governance (no daemon) — same shape, native PyO3 runtime.
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
