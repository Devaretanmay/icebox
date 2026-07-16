# SDK: Python

`pip install icebox-sdk` gives you the `Workspace` abstraction, which automatically manages the ICEBOX daemon, charter, scope, and API communications for your AI agents.

```sh
pip install icebox-sdk
```

The SDK seamlessly acts as a proxy for the `icebox-daemon` binary. You no longer need to worry about C ABIs or compiling native libraries. The interactive setup wizard (run via `icebox`) handles everything for you.

## The Workspace Abstraction

The `Workspace` class provides a high-level orchestration interface ideal for agentic loops.

```python
from icebox import Workspace

# 1. Initialize the Workspace
# This automatically accepts the charter and adds the target to the allowed scope
workspace = Workspace(target="127.0.0.1")

# 2. Run a task
# The workspace proxies the request to the underlying REST API
try:
    outcome = workspace.execute(
        module="recon",
        sandbox=True,
        approved=True
    )
    print("Success:", outcome)
except Exception as e:
    print("Governance Blocked:", e)

# 3. Retrieve the audit trail
audit_log = workspace.audit(n=10)
print(audit_log)
```

## Raw REST API Wrapper

If you want low-level control over the REST API without the automatic scoping provided by `Workspace`, use the `IceboxClient`:

```python
from icebox import IceboxClient

client = IceboxClient("http://127.0.0.1:8443")
client.accept_charter("10.0.0.0/8")
client.add_scope("10.0.0.5")

outcome = client.run_module(
    module_name="scan",
    target="10.0.0.5",
    sandbox=False,
    approved=True,
    options={"host": "10.0.0.5", "ports": "1-1024"}
)
```

## API Reference

| Class/Method | Purpose |
| --- | --- |
| `Workspace(target, url)` | Construct a governed workspace for a specific target. Automatically handles charter and scope. |
| `Workspace.execute(module, sandbox, approved, options)` | Run a module against the workspace target. |
| `Workspace.audit(n)` | Fetch the last `n` audit logs as JSON. |
| `IceboxClient(url)` | Raw REST client for precise control over the daemon API. |
