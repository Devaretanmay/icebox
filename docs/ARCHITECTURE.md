# Architecture

ICEBOX reduces to one irreducible primitive:

> **Give an autonomous workflow a temporary, isolated place to run and fail, so
> reality only ever sees the first success.**

ICEBOX never executes the agent's results against reality. The agent does.

```
                    AI AGENT
                       |
                  icebox()  ->  open a Session
                       |
                       v
                ENTER (isolated)
                       |
                       v
                EXECUTE workflow
                       |
                       v
                exit 0 ?  ---- NO ---- refactor -> retry (inside Session)
                       |
                      YES
                       v
                EXIT  -> artifacts + status returned
                       |
                       v
                Agent applies results to reality
```

## Layers

```
THE PRODUCT

- icebox() / Session   open + run + exit a staging Session
- icebox init          pick a Session profile (onboarding)
- icebox doctor        Docker / Session / plugin health
- examples/            recipes: claude_code, openai_agents, crewai, autogen

        ↓

THE SESSION (isolated, temporary, always audited)

- enter    -> provision an isolated environment (Docker)
- execute  -> run a Python callable or CLI command group
- validate -> optional; default = exit 0
- retry    -> on failure, re-run inside the same Session (infinite)
- exit     -> tear down container, return artifacts + status
- audit    -> built in: attempts, failures, duration, artifacts, history

        ↓

OPTIONAL PLUGINS (mounted only when needed)

- Governance    (v1 kernel, preserved, off by default)
- NetworkPolicy (egress isolation, reuses src/core/proxy)
- ResourceLimits

        ↓

THE AGENT'S WORLD (the agent's responsibility, not ICEBOX's)

- AWS, GitHub, Filesystems, Infrastructure, Pentesting tooling, Cloud APIs
```

## What is deliberately absent

These do not belong in the core product:

- Generic process hosting / container platform (we are not Daytona/E2B/Modal).
- Mandatory governance, policy engines, approval gates (those are a plugin).
- "AI OS" / agent runtime / execution layer / operating-system framing.

## The one invariant

Failure inside a Session is free. The agent may iterate forever; the container
is destroyed on exit and reality is never touched unless the agent applies the
results itself. Audit records what happened so the human can inspect it.
