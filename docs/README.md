# ICEBOX Documentation

The whole product fits on the README. Start there: [`README.md`](../README.md).

## The two ideas

1. **Protect something** — `icebox init` sets up the guardrails.
2. **Govern dangerous actions** — `govern()` answers one question: is this allowed?

## How to use

```bash
pip install icebox-sdk
icebox init
```

```python
from icebox import govern

if govern("Delete EC2 Instance", target="Production AWS"):
    delete_ec2()
```

ICEBOX decides the capability, the policy, and the verdict. You just describe
the action in plain words.

## Commands

- `icebox init` — what do you want to protect? Sets up policy, scope, audit.
- `icebox doctor` — confirms you're actually protected (daemon, policy, audit,
  sandbox, profile).

## `govern()` reference

```python
govern(action, target=None, capability=None, impact="low",
       destructive=False, verbose=True) -> GovernResult
```

- `action`: what the agent wants to do, in plain words.
- `target`: what it acts on (a host, account, or scope name).
- `capability`: usually omitted — ICEBOX infers it.
- `impact`: `"low" | "medium" | "high" | "critical"`.
- `destructive`: `True` if the action can't be undone.
- `verbose`: print a short notice when an action is held or blocked.

`GovernResult` is truthy when allowed, so `if govern(...):` reads naturally.
It also exposes `.allowed`, `.decision` (`allow` / `require_approval` /
`deny`), `.reason`, and `.decision_id`.

## Examples

Framework recipes (not integrations) live in [`examples/`](../examples):

- `claude_code.py`
- `openai_agents.py`
- `crewai.py`
- `autogen.py`

Each wraps a tool call in `govern()` — run it only when allowed.

## Notes

- The daemon (`icebox-daemon --api`) must be running for `govern()` to work.
- On Linux, network isolation uses network namespaces. On other platforms the
  proxy provides monitoring and audit, not hard containment.
- Advanced users can still use the lower-level `IceboxClient` / `GovernClient`
  / `Workspace` surfaces, but most people never need them.
