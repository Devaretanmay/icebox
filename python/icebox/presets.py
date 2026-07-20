"""Opinionated ICEBOX profiles.

The user never writes policy. They say what they want to protect and where it
runs, and ICEBOX decides the rest. This module is the only place policy
knowledge lives.
"""

# Capabilities the kernel understands (kept here so the wizard never has to
# explain them to the user).
_DESTRUCTIVE_CAPS = [
    "privilege_escalation",
    "lateral_movement",
    "credential_access",
    "persistence",
    "filesystem_modification",
]


def _require_approval(cap, pattern="*"):
    return {"require_approval": {"capability": cap, "target_pattern": pattern}}


def _deny(cap):
    return {"deny_capability": cap}


# What the user wants to protect. Four presets + custom. No more.
PROTECT_WHAT = {
    "1": ("AWS", "aws"),
    "2": ("Production Infrastructure", "prodinfra"),
    "3": ("Pentesting Agent", "pentest"),
    "4": ("Development Environment", "dev"),
    "5": ("Custom", "custom"),
}

ENVIRONMENTS = {
    "1": ("Development", "development"),
    "2": ("Staging", "staging"),
    "3": ("Production", "production"),
}


def build_profile(protect_key: str, env_key: str, approval: bool,
                  deny_destructive: bool, scope: str = "*") -> dict:
    """Return an opinionated profile for the wizard to apply.

    The user picks what to protect and where it runs. Everything else
    (sandbox, audit, approval, exfil-block) is decided here.
    """
    protect_label, protect_kind = PROTECT_WHAT[protect_key]
    env_label, environment = ENVIRONMENTS[env_key]

    sandbox = True
    audit = True

    rules = []
    if approval:
        for cap in _DESTRUCTIVE_CAPS:
            rules.append(_require_approval(cap))
    if deny_destructive:
        rules.append(_deny("data_exfiltration"))

    # Production always protects itself, even if the user was permissive.
    if environment == "production":
        for cap in _DESTRUCTIVE_CAPS:
            if not any(r.get("require_approval", {}).get("capability") == cap
                       for r in rules):
                rules.append(_require_approval(cap))
        if not any("deny_capability" in r for r in rules):
            rules.append(_deny("data_exfiltration"))

    # Development only looks at the worst actions unless told otherwise.
    if environment == "development" and not approval and not deny_destructive:
        rules.append(_require_approval("privilege_escalation", "*"))

    name = f"{env_label} {protect_label}"
    summary = [
        f"Sandbox: {'on' if sandbox else 'off'}",
        f"Audit: {'on' if audit else 'off'}",
        f"Approval: {'required for dangerous actions' if approval or environment == 'production' else 'off'}",
        f"Destructive/exfil: {'blocked by default' if deny_destructive or environment == 'production' else 'allowed'}",
    ]
    return {
        "name": name,
        "protect_kind": protect_kind,
        "environment": environment,
        "sandbox": sandbox,
        "audit": audit,
        "approval": approval or environment == "production",
        "deny_destructive": deny_destructive or environment == "production",
        "policy": rules,
        "summary": summary,
        "scope": scope,
        "engagement": f"{protect_kind}-{environment}",
    }
