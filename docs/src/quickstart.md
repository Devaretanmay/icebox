# Quickstart

ICEBOX is **local-first and account-free**. You accept a charter, declare a
scope, then run governed modules through the seam.

## 1. Start the CLI + REST API

```sh
icebox            # interactive REPL on :8443 REST API
icebox --api     # REST API only
```

## 2. Accept a charter and add a scope

```text
icebox> charter accept "authorization test"
icebox> scope add 10.0.0.0/24
```

## 3. List and run a module

```text
icebox> list
icebox> use tcp_port_scanner
icebox> set host 10.0.0.5
icebox> run
```

High-risk modules are blocked unless you explicitly opt in:

```text
icebox> run --approve 10.0.0.5
```

## 4. Govern an agent programmatically (Python)

```python
from icebox import Governance

gov = Governance({
    "charter": "authorized engagement",
    "scope": ["10.0.0.0/24"],
    "max_risk": "high",
})
outcome = gov.run({
    "module": "tcp_port_scanner",
    "target": "10.0.0.5",
    "options": {"host": "10.0.0.5", "ports": "1-1024"},
})
print(outcome)            # decision, audit trail, evidence
print(gov.audit_json())   # full audit log
```

## 5. Continuous validation

```text
icebox> validate run --targets 10.0.0.5 --model llama3.2
icebox> validate diff before.json after.json
```

The REST API is served at `http://127.0.0.1:8443/api/v1` for
non-interactive integrations.
