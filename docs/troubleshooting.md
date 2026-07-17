# Troubleshooting Guide

When you put a hard boundary between offensive tools and their execution, you are going to hit blocks. That is by design. 

If ICEBOX is blocking your execution, it means the Governance Seam is doing its job. Here are the most common blocks you will encounter and exactly how to resolve them.

### "charter not accepted - run `charter accept` first"
**The Problem:** ICEBOX strictly forbids any module execution until a legal or operational charter has been explicitly accepted for the session.
**The Solution:**
- **CLI**: Run `charter accept --engagement my-audit`
- **REST**: Send a POST to `/api/v1/charter` with `{"engagement": "my-audit", "rules_of_engagement": []}`
- **Python**: Pass `"charter": {"accepted": True, "engagement": "my-audit"}` in the `Governance` initialization dictionary.

### "target out of scope: 10.0.0.5"
**The Problem:** You tried to scan or exploit a target that has not been explicitly allow-listed in the current scope.
**The Solution:**
- **CLI**: Run `scope add 10.0.0.5` or `scope add 10.0.0.0/24`
- **REST**: Send a POST to `/api/v1/scope` with `{"target": "10.0.0.5"}`
- **Python**: Ensure your `allow` array in the `scope` dictionary includes the target.

### "risk level high exceeds maximum allowed low"
**The Problem:** The module you are trying to run requires a higher risk tolerance than the Governance Engine is currently configured to allow.
**The Solution:**
If you genuinely need to run this action, you must approve it:
- **CLI**: Rerun your command with the `--approve` flag (e.g., `run --approve 127.0.0.1`).
- **REST**: Ensure you pass `"approved": true` in your module execution POST request.
- **Python SDK**: If the engine returns `NeedsApproval`, capture the `decision_id` from the payload and pass it to `gov.approve(decision_id)`. Then, rerun the action.

### "forbidden: admin role required"
**The Problem:** You are trying to apply a Policy Pack, change the active role, or modify core rules, but you are currently logged in as an `operator`.
**The Solution:**
- **CLI**: Run `role --set admin` (Note: In a true production deployment, role escalation would be tied to your IAM provider).

### "module not found"
**The Problem:** You are trying to use a module name that ICEBOX does not recognize.
**The Solution:**
Check your spelling. ICEBOX uses snake_case for module names (e.g., `vuln_scanner`, `recon`, `port_scanner`). If you are developing a custom module, ensure you have correctly annotated your Rust struct with `#[module(name = "my_tool")]` and recompiled the binary.

### "cargo metadata failed: No such file or directory" (vuln_scanner only)
**The Problem:** You ran the `vuln_scanner` without telling it where the Rust project is located.
**The Solution:**
- **CLI**: Run `set project_dir /path/to/repo` before running the module.
- **REST/Python**: ICEBOX modules map missing fields appropriately if handled by the module, but the easiest fix is ensuring your `target` string maps to the absolute path of the repository.
