# ICEBOX

ICEBOX protects your AI agent from doing stupid things.

## Install

```bash
pip install icebox-sdk
icebox init
```

`icebox init` asks what you want to protect and sets everything up. No YAML,
no policy DSL, nothing to configure.

## Use it

```python
from icebox import govern

if govern("Delete EC2 Instance", target="Production AWS"):
    delete_ec2()
```

That's the whole SDK. Describe the action in plain words; ICEBOX decides
whether it's allowed. If `govern(...)` is truthy, do it. If not, ICEBOX already
stopped it and saved the audit entry.

When an action is held or blocked, ICEBOX tells you:

```
ICEBOX protected Production AWS.

Action:
  Delete EC2 Instance

Decision:
  Approval Required

Your AI agent attempted a dangerous action and was stopped.
```

## Check your protection

```bash
icebox doctor
```

```
ICEBOX Status

✓ Daemon running
✓ Policy loaded (6 rules)
✓ Audit enabled
✓ Sandbox enabled
✓ Production AWS profile loaded

You're protected.
```

## Examples

ICEBOX works in front of any agent framework. Recipes, not integrations:

* [Claude Code](examples/claude_code.py)
* [OpenAI Agents SDK](examples/openai_agents.py)
* [CrewAI](examples/crewai.py)
* [AutoGen](examples/autogen.py)

Each is a thin wrapper: intercept the tool call, ask `govern()`, run only when
allowed.

## The two ideas

1. **Protect something.** `icebox init` sets up the guardrails.
2. **Govern dangerous actions.** `govern()` answers one question: is this allowed?

Everything else — sandboxes, audit trails, approval workflows — is ICEBOX's
job, not yours.
