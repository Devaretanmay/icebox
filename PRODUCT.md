# ICEBOX — Product Identity

## What ICEBOX is, in one sentence

> ICEBOX is a staging environment for autonomous workflows: a temporary,
> isolated place where an agent runs its whole workflow and fails as many times
> as it wants, so reality only ever sees the first success.

ICEBOX never mutates reality. The agent applies the results itself.

## The primitive

```
enter → execute → [validate] → (fail → refactor → retry) → exit
```

- **enter**: open an isolated ICEBOX Session (Docker by default).
- **execute**: run the agent's workflow — a Python callable or a CLI command
  group — inside the Session.
- **validate**: *optional*. The default success gate is "exited 0". Custom
  validators are an advanced opt-in.
- **retry**: on failure the agent refactors and re-runs inside the *same*
  Session. Infinite by default. Reality never sees the failures.
- **exit**: return artifacts + final status; the Session is destroyed.

## Architecture

```
THE PRODUCT

- icebox()            open a Session
- session.run()       run a Python callable or CLI command group
- icebox init         pick a Session profile (onboarding)
- icebox doctor       Docker / Session / plugin health
- examples/           recipes: claude_code, openai_agents, crewai, autogen

        ↓

THE SESSION (isolated, temporary)

- enter  -> provision an isolated environment
- execute -> run the agent's workflow
- exit   -> tear down, return artifacts + status
- built-in audit: every Session records its own execution history

        ↓

OPTIONAL PLUGINS (mounted only when needed)

- Governance   (v1 kernel, off by default)
- NetworkPolicy (egress isolation)
- ResourceLimits

        ↓

THE AGENT'S WORLD (governed by the agent, not by ICEBOX)

- AWS
- GitHub
- Filesystems
- Infrastructure
- Pentesting tooling
- Cloud APIs
```

## What ICEBOX is NOT

- A governance/safety/security product by default (governance is an optional
  plugin).
- A container platform / generic process host. The Session hosts autonomous
  *workflows* (Python callables, CLI command groups), not arbitrary workloads.
- An agent runtime, an OS kernel, or an "AI operating system."

## Status: v2.0.0-beta

The Session engine is the product. Governance is preserved as an optional
plugin so v1 users keep their `govern()` API.

## The boring-infrastructure principle

Agents already plan, execute, and iterate. ICEBOX just gives them a place to
do the dangerous part — touching reality — only after they've succeeded in
isolation. The strongest version of ICEBOX is the most invisible one:

```
pip install icebox-sdk
  ↓
icebox init
  ↓
with icebox() as s:
    s.run(my_agent.run_task)
  ↓
Never worry about the agent breaking reality again.
```

## Decisions (founder, 2026-07)

- **Freeze the "sandbox/platform" framing.** ICEBOX is a staging environment,
  not a container product. We do not compete with Daytona / E2B / Modal / Docker.
- **Keep audit built in.** Session artifacts and execution history are
  fundamental, not optional.
- **Keep `icebox init` and `icebox doctor`.** Onboarding and health checks are
  adoption-critical; repurposed for Sessions, not deleted.
- **Make `validate()` optional.** Default = exit 0. Custom validators are
  advanced. The product must be adoptable in thirty seconds.
- **Phase 1 execution seam = Python callables + CLI command groups only.** No
  arbitrary subprocess hosting (yet).
- **Preserve v1 governance as a plugin.** It was good work; it becomes
  `icebox-governance`, off by default.
- **Kill "sandbox"/"kernel" product language.** The Box is an ICEBOX Session.
