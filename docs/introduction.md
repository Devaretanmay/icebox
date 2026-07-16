# Welcome to ICEBOX

Let's face it: giving autonomous agents the ability to run offensive security tools is a terrifying prospect. 

One minute your agent is scanning for open ports on a staging environment, and the next it's hallucinating an SQL injection payload against your production database because it got confused by a prompt. The offensive security space needs automation, but it absolutely cannot afford reckless automation.

That's exactly why we built **ICEBOX**.

## The Governance Seam

ICEBOX is the runtime governance layer for autonomous security agents and offensive security tooling. We put a hard, auditable boundary between these agents and the targets they are trying to interact with. We call this boundary the **Governance Seam**.

Instead of letting an agent call `nmap` or an exploit script directly, you force all execution through ICEBOX. Before a single packet hits the wire, ICEBOX intercepts the request, evaluates the risk, checks the operational scope, verifies the legal charter, and makes a hard decision: `Allow`, `Block`, or `NeedsApproval`.

## Write Once, Govern Everywhere

We didn't want to force you into a specific language ecosystem. ICEBOX acts as the central brain, but you can interact with it wherever you are most comfortable:

- **The CLI**: A fully interactive REPL for human operators.
- **The REST API**: A lightning-fast web server for orchestrating multi-agent systems and dashboard integrations.
- **The Rust SDK**: Native memory-safe execution for high-performance tooling.
- **The Python SDK**: C-ABI bindings that let data scientists and AI engineers govern their scripts natively.

## Stop Hallucinations Before They Do Damage

By explicitly defining your Rules of Engagement, Max Risk Tolerance, and Scope Allow-lists in ICEBOX, you strip the decision-making power away from the LLM. If the agent hallucinates and attempts to execute a high-risk exploit out of scope, ICEBOX simply blocks it, records the failure in an immutable audit log, and lets the agent try again.

You get all the speed and scalability of AI-driven security, with the ironclad guarantees of deterministic policy enforcement.

Ready to lock down your tooling? Let's jump into the quickstart.
