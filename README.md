# ICEBOX

ICEBOX gives your AI agent a safe place to fail.

It's a **staging environment for autonomous workflows**. An agent enters a
Session, runs its whole workflow in isolation, and may fail as many times as it
wants. Reality only ever sees the first success. ICEBOX never mutates reality
itself — the agent applies the results.

> Let your AI agent fail 10,000 times. Reality only sees the first success.

## Install

```bash
pip install icebox-sdk
icebox init
```

`icebox init` picks a Session profile in about thirty seconds. No YAML, no
policy DSL.

## Use it

```python
from icebox import icebox

with icebox() as session:
    session.run(my_agent.run_task)
```

That's the whole SDK. The agent runs inside the Session; ICEBOX retries on
failure (default: until the workflow exits 0) and records what happened. When
it succeeds, the Session exits and you get the artifacts.

```python
with icebox(profile="aws") as session:
    session.run_cli("python deploy.py")
```

A CLI command group works too.

## Check your setup

```bash
icebox doctor
```

```
ICEBOX Status

✓ Docker available
✓ Docker daemon running
✓ default profile loaded
✓ Audit built in to every Session

You're ready to stage autonomous workflows.
```

## Examples

ICEBOX works in front of any agent framework. Recipes, not integrations:

* [Claude Code](examples/claude_code.py)
* [OpenAI Agents SDK](examples/openai_agents.py)
* [CrewAI](examples/crewai.py)
* [AutoGen](examples/autogen.py)

Each gives the agent a Session and lets it iterate safely.

## The two ideas

1. **Stage the workflow.** `icebox()` opens a temporary, isolated Session.
2. **Let it iterate.** Failure inside the box is free; reality stays untouched.

Everything else — governance, network policy, resource limits — is an optional
plugin you mount when you need it. Audit is always on.

## Governance is optional

ICEBOX v2 does not govern by default. If you want the v1 "is this action
allowed?" gating, mount it:

```python
from icebox import icebox
from icebox.governance import Governance

with icebox(plugins=[Governance()]) as session:
    session.run(my_agent.run_task)
```
