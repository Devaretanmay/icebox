# Security Policy

## Supported Versions

ICEBOX is in its early release phase (v0.x). Security patches will be prioritized for the
latest release only.

| Version | Supported          |
|---------|--------------------|
| 0.x     | Active development |

## Reporting a Vulnerability

ICEBOX governs autonomous offensive security tools — a vulnerability in the
governance seam itself is a critical issue. We take security reports seriously.

### Private Disclosure

**Do not file a public issue for security vulnerabilities.**

Please report vulnerabilities privately via one of these methods:

1. **GitHub Security Advisory:** Navigate to the repository's
   [Security tab](https://github.com/Devaretanmay/icebox/security/advisories) and open a
   new advisory.
2. **Email:** Send details to the project maintainers (check the repository for
   current contact information).

### What to Include

To help us triage and fix issues quickly, please include:

- **Type of vulnerability** (e.g., policy bypass, privilege escalation,
  information disclosure, audit trail manipulation)
- **Steps to reproduce** — minimal code and configuration needed to demonstrate
  the issue
- **Impact** — what an attacker could achieve (e.g., "an agent can bypass the
  approval gate by exploiting X")
- **Suggested fix** (optional, but appreciated)

### Response Timeline

| Timeframe | Action |
|---|---|
| Within 48 hours | Acknowledgment of receipt |
| Within 5 business days | Initial triage and severity assessment |
| Within 14 days | Patch released or mitigation communicated |

### Severity Guidelines

| Severity | Example |
|---|---|
| **Critical** | Policy bypass allows ungoverned execution on any target |
| **High** | Privilege escalation (viewer → admin), audit trail forgery |
| **Medium** | Information disclosure (evidence or audit data to unauthorized role) |
| **Low** | Minor race condition in non-critical path |

## Scope

The following are **in scope** for security reports:

- The governance seam (`icebox::core` executor, policy engine, approval engine)
- Audit trail integrity (`icebox::core` audit)
- Evidence provenance and integrity (`icebox::core` evidence)
- RBAC enforcement (all crates)
- REST API authentication and authorization (`icebox::interfaces`)
- SDK integrity (`python/icebox`)
- Supply chain (compromised dependencies)

The following are **out of scope**:

- The example offensive modules in `src/modules` (they are demos)
- Third-party AI models (Ollama, etc.)
- Issues in dependencies that are already reported upstream

## Recognition

We maintain a list of security researchers who have responsibly disclosed
vulnerabilities. With your permission, we will acknowledge your contribution in
release notes and this file.

## Safe Harbor

We consider security research conducted under this policy as:

- Authorized in accordance with applicable law
- Exempt from any restrictions in the project's license that would inhibit
  security testing

You are expected to:

- Make a good faith effort to avoid privacy violations and service disruption
- Not access or modify data beyond what is necessary to demonstrate the vulnerability
- Not exploit the vulnerability beyond what is necessary to demonstrate it

---

**Thank you for helping keep autonomous security governance safe.**
