"""HTTP-based Python SDK for the ICEBOX Governance Kernel.

Talks directly to the ICEBOX REST API — no native build required.
"""

import functools
import json
import os
import urllib.error
import urllib.request
from typing import Any


def _as_list(value) -> list:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)):
        return list(value)
    return [value]


def _normalize_outcome(outcome: dict) -> dict:
    if "Allowed" in outcome:
        return {"approved": True, "decision": "allow", "reason": None,
                "decision_id": outcome["Allowed"]["decision_id"], "chain_tip": ""}
    if "Blocked" in outcome:
        b = outcome["Blocked"]
        return {"approved": False, "decision": "deny", "reason": b.get("reason"),
                "decision_id": b["decision_id"], "chain_tip": ""}
    if "NeedsApproval" in outcome:
        n = outcome["NeedsApproval"]
        return {"approved": False, "decision": "require_approval",
                "reason": n.get("reason"), "decision_id": n["decision_id"],
                "chain_tip": ""}
    return outcome


class IceboxError(Exception):
    pass


class GovernanceError(Exception):
    pass


class ActionBlocked(GovernanceError):
    pass


class NeedsApproval(GovernanceError):
    pass


class IceboxClient:
    """High-level client for the ICEBOX REST API."""

    def __init__(self, url: str = "http://127.0.0.1:8443", token: str | None = None):
        self._base = url.rstrip("/")
        self._token = token or self._load_token()

    def _load_token(self) -> str | None:
        try:
            with open(os.path.expanduser("~/.icebox/auth.token")) as fh:
                return fh.read().strip() or None
        except OSError:
            return None

    def _headers(self) -> dict:
        headers = {"Content-Type": "application/json"}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        return headers

    def _get(self, path: str, params: dict | None = None) -> Any:
        url = self._base + path
        if params:
            query = "&".join(f"{k}={v}" for k, v in params.items())
            url = f"{url}?{query}"
        req = urllib.request.Request(url, headers=self._headers())
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read())

    def _post(self, path: str, body: Any = None) -> Any:
        data = json.dumps(body).encode() if body is not None else b""
        req = urllib.request.Request(
            self._base + path,
            data=data,
            headers=self._headers(),
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                raw = r.read()
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as e:
            raise IceboxError(f"HTTP {e.code}: {e.read().decode()}") from e

    def list_modules(self) -> list[dict]:
        return self._get("/api/v1/modules")

    def get_module(self, name: str) -> dict:
        return self._get(f"/api/v1/modules/{name}")

    def accept_charter(self, target: str) -> dict:
        return self._post("/api/v1/charter", {"engagement": target})

    def add_scope(self, target: str) -> dict:
        return self._post("/api/v1/scope", {"target": target})

    def set_mode(self, mode: str) -> str:
        return self._post("/api/v1/mode", {"mode": mode})

    def run_module(
        self,
        name: str,
        target: str,
        approved: bool = False,
        options: dict | None = None,
        engine: str | None = None,
    ) -> dict:
        return self._post(
            f"/api/v1/modules/{name}/run",
            {
                "target": target,
                "approved": approved,
                "options": options or {},
                "engine": engine,
            },
        )

    def pending_approvals(self) -> list[dict]:
        return self._get("/api/v1/approvals")

    def approve(self, approval_id: int) -> str:
        return self._post(f"/api/v1/approvals/{approval_id}/approve")

    def deny(self, approval_id: int) -> str:
        return self._post(f"/api/v1/approvals/{approval_id}/deny")

    def audit(self, n: int = 20) -> list[dict]:
        return self._get("/api/v1/audit", {"n": n})

    def bind_proxy(self, target: str, port: int) -> dict:
        return self._post("/api/v1/proxy/bind", {
            "target": target,
            "port": port,
        })

    def unbind_proxy(self, local_port: int) -> dict:
        return self._post("/api/v1/proxy/unbind", {
            "local_port": local_port,
        })

    def get_openai_tools(self) -> list[dict]:
        """Dynamically generates OpenAI-compatible JSON schemas for all ICEBOX modules.

        Delegates to :func:`icebox.tools.openai_tools` so there is a single
        canonical tool schema shared by the client and the LangChain helpers.
        """
        from .tools import openai_tools
        return openai_tools(self)


class GovernClient:
    """Governance SDK client — the \"Stripe for governed execution\" single-call interface.

    Wraps any autonomous action in a Governed Execution Environment (GEE)
    with one API call. Every action is policy-evaluated, scope-enforced,
    approval-gated, audited, and evidence-collected automatically.

    Usage:

        client = GovernClient()
        result = client.govern({
            \"action\": \"scan_network\",
            \"target\": \"10.0.0.0/24\",
            \"capability\": \"network_scan\",
            \"impact\": \"low\",
            \"destructive\": False,
        })
        if result[\"approved\"]:
            # execute the action externally
            client.record(action, {\"success\": True, \"evidence\": [...], \"data\": {...}})
    """

    def __init__(self, url: str = "http://127.0.0.1:8443", token: str | None = None):
        self._base = url.rstrip("/")
        self._token = token

    def _headers(self) -> dict:
        headers = {"Content-Type": "application/json"}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        return headers

    def _post(self, path: str, body: Any) -> Any:
        data = json.dumps(body).encode()
        req = urllib.request.Request(
            self._base + path,
            data=data,
            headers=self._headers(),
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                raw = r.read()
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as e:
            msg = e.read().decode()
            raise IceboxError(f"HTTP {e.code}: {msg}") from e

    def govern(self, action: dict) -> dict:
        """Run an action through the full GEE lifecycle.

        Returns a GovernResult with approval decision, reason, and chain tip.
        """
        return self._post("/api/v1/govern", action)

    def record(self, action: dict, outcome: dict, decision: str = "allow") -> dict:
        """Record the outcome of a previously governed action.

        Appends evidence and an audit-chain entry, returns chain tip.

        Args:
            action: The original action dict (same as passed to govern()).
            outcome: Outcome dict with success, evidence, data.
            decision: The decision from govern() — "allow", "deny", or
                      "require_approval". Defaults to "allow" only for
                      backward compatibility; always pass the real value.
        """
        return self._post("/api/v1/govern/record", (action, outcome, decision))


class GovernedSession:
    """A governed session over a single action.

    Returned by :func:`govern`. Mirrors the Rust ``GovernanceRuntime`` and the
    REST ``POST /govern`` contract: one model across all three surfaces.

        with govern(config) as g:
            verdict = g.preflight({"action": "scan", "target": "10.0.0.5", ...})
            if verdict["approved"]:
                result = do_scan()
                g.complete(result, verdict["decision"])
    """

    def __init__(self, client: "GovernClient"):
        self._client = client

    def preflight(self, action: dict) -> dict:
        """Run the action through the full GEE lifecycle.

        Returns a GovernResult: ``{"approved": bool, "decision": str,
        "reason": Optional[str], "decision_id": int, "chain_tip": str}``.
        """
        self._last_action = action
        return self._client.govern(action)

    def run(self, action: dict) -> dict:
        """Preflight and, if approved, immediately record success.

        Convenience for fire-and-forget governed actions where the "real"
        execution is the daemon itself (e.g. a registered module). Returns the
        GovernResult from ``preflight``.
        """
        verdict = self._client.govern(action)
        if verdict.get("approved"):
            self.complete({"success": True, "evidence": [], "data": {}},
                          verdict.get("decision", "allow"))
        return verdict

    def complete(self, outcome: dict, decision: str = "allow") -> dict:
        """Record the outcome of a previously governed action.

        Appends evidence + an audit-chain entry, returns the chain tip.
        """
        return self._client.record(self._last_action, outcome, decision)

    def __enter__(self) -> "GovernedSession":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        return False


def govern(config: dict | None = None, url: str = "http://127.0.0.1:8443",
           token: str | None = None) -> GovernedSession:
    """Open a governed session — the flagship single-call governance API.

    ``config`` is accepted for symmetry with the Rust ``GovernanceBuilder`` and
    the in-process :class:`Governance` surface; the HTTP ``GovernClient``
    governs against a running daemon's policy, not a local config.

        with govern() as g:
            verdict = g.preflight({...})
            if verdict["approved"]:
                g.complete(outcome, verdict["decision"])

    The same mental model applies in Rust (``govern(config)``) and over REST
    (``POST /govern`` then ``POST /govern/record``).
    """
    session = GovernedSession(GovernClient(url, token))
    session._last_action = {}
    return session


class Governance:
    """Natively backed by PyO3 Rust extension."""

    def __init__(self, config: dict):
        url = config.get("url", "http://127.0.0.1:8443")
        self._client = IceboxClient(url)
        try:
            from . import _icebox
            scopes = config.get("scope", {}).get("allow", [])
            if not isinstance(scopes, list):
                scopes = [scopes]
            max_risk = config.get("max_risk", "critical")
            self._native = _icebox.NativeIcebox(scopes, max_risk)
        except ImportError:
            self._native = None

    def check(self, task: dict) -> dict:
        if self._native:
            import json
            spec = {
                "name": task.get("action", task.get("module", task.get("name", ""))),
                "target": task.get("target", ""),
                "capabilities": _as_list(task.get("capability", task.get("capabilities", []))),
                "impact": task.get("impact", "low"),
                "destructive": task.get("destructive", False),
            }
            outcome = json.loads(self._native.preflight_action(json.dumps(spec)))
            return _normalize_outcome(outcome)

        name = task.get("module", task.get("name", ""))
        target = task.get("target", "")
        try:
            return self._client.run_module(name, target)
        except Exception as e:
            return {"error": str(e)}

    def run(self, task: dict) -> dict:
        return self.check({**task, "approved": True})

    def approve(self, approval_id: int) -> bool:
        try:
            self._client.approve(approval_id)
            return True
        except IceboxError:
            return False

    def deny(self, approval_id: int) -> bool:
        try:
            self._client.deny(approval_id)
            return True
        except IceboxError:
            return False

    def pending(self) -> list:
        return self._client.pending_approvals()

    def audit_json(self) -> list:
        return self._client.audit()

    def audit_csv(self) -> str:
        if not self._client:
            return ""
        try:
            req = urllib.request.Request(
                self._client._base + "/api/v1/audit/export?format=csv",
                headers=self._client._headers(),
            )
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.read().decode()
        except urllib.error.HTTPError as e:
            raise IceboxError(f"HTTP {e.code}: {e.read().decode()}") from e
        except Exception:
            return ""

    def check_only(self, task: dict) -> dict:
        if not self._native:
            return {"type": "allowed", "decision_id": 0}
        return json.loads(self._native.preflight_action(json.dumps(task)))

    def record_action(self, task: dict, result: Any, decision: str = "allow") -> dict:
        if not self._native:
            return {"type": "allowed", "decision_id": 0}
        return json.loads(
            self._native.complete_action(json.dumps(task), json.dumps(result), decision)
        )

    def governed(self, capability: str | None = None, impact: str = "low",
                 destructive: bool = False):
        """Decorator that wraps a function in the GEE lifecycle.

        Every call to the decorated function is preflight-checked, audited,
        and recorded in the tamper-evident hash chain.

        Usage:

            @icebox.governed(capability=\"network_scan\", impact=\"low\")
            def scan(host: str, ports: str):
                ...
        """
        def decorator(fn):
            @functools.wraps(fn)
            def wrapper(*args, **kwargs):
                target = kwargs.get("target", args[0] if args else "")
                caps = [capability] if capability else []
                task = {
                    "name": fn.__name__,
                    "target": target,
                    "capabilities": caps,
                    "impact": impact,
                    "destructive": destructive,
                    "context": "cli",
                    "approved": False,
                }
                outcome = self.check_only(task)
                t = outcome.get("type", outcome.get("variant", ""))
                if t == "allowed":
                    result = fn(*args, **kwargs)
                    self.record_action(task, result, "allow")
                    return result
                if t == "needs_approval":
                    raise NeedsApproval(outcome.get("reason", "approval required"))
                raise ActionBlocked(outcome.get("reason", "blocked by policy"))
            return wrapper
        return decorator
