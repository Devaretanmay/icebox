# Introduction

ICEBOX is a **single governance seam** that every human operator, REST
client, and LLM agent must pass through before anything touches a target.

```text
Human / CLI / REST Client / LLM Agent / Multi-Agent
                       │
                ┌────────▼────────┐
                │  ModuleExecutor  │   ← THE SEAM
                │  ::execute()     │
                └────────┬────────┘
                       │
                ┌────────▼────────┐
                │   Policy Engine  │   6 rule types, CVSS/EPSS/KEV-aware
                └────────┬────────┘
                       │
                ┌────────▼────────┐
                │  Approval Engine │   queue + gates
                └────────┬────────┘
                       │
                ┌────────▼────────┐
                │   Audit Engine   │   JSON + CSV
                └────────┬────────┘
```

Because the gate is in exactly one place, you can prove what an agent was
allowed to do, why, and whether the governance actually held. The offensive
modules are just examples that exercise the seam.

There is no account and no login required to use it — it runs locally
against a workspace you control.
