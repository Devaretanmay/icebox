# SDK: Python

`pip install icebox-sdk` gives you `icebox.Governance`, which drives
the same charter / scope / risk / approval gates that guard native
ICEBOX modules — so any Python agent can be governed by the single seam.

```sh
pip install icebox-sdk
```

The SDK wraps the compiled `libicebox` C ABI via `ctypes`. If the
native lib is not found, build it (`cargo build`) or set
`ICEBOX_CAPI` to its path.

## Govern a task

```python
from icebox import Governance

gov = Governance({
    "charter": {"accepted": True, "engagement": "demo", "rules_of_engagement": []},
    "scope": {"allow": ["10.0.0.0/24"]},
    "max_risk": "high",
    "role": "admin",
})

task = {
    "name": "scan",
    "target": "10.0.0.5",
    "capabilities": ["network_scan"],
    "impact": "low",
    "destructive": False,
    "options": {"host": "10.0.0.5", "ports": "1-1024"},
}

# Supervised: approval-gated tasks return a "NeedsApproval" decision.
outcome = gov.check(task)
# Unsupervised: approval-gated tasks are auto-granted.
outcome = gov.run(task)

print(outcome)              # e.g. {"Allowed": {"result": null, "decision_id": 1}}
print(gov.audit_json())    # full audit log as JSON
print(gov.audit_csv())     # same, as CSV
```

## API

| Method | Purpose |
| --- | --- |
| `Governance(config)` | Construct a governed runtime from a dict. |
| `.check(task)` | Supervised evaluation; approval-gated tasks return `NeedsApproval`. |
| `.run(task)` | Unsupervised evaluation; approval-gated tasks are auto-granted. |
| `.approve(id)` / `.deny(id)` | Resolve a pending approval request. |
| `.pending()` | List pending approval requests. |
| `.audit_json()` / `.audit_csv()` | Export the full audit trail. |

## Examples

See `python/examples/governed_agent.py` for a complete governed-agent
loop.
