"""HTTP-based Python SDK for the ICEBOX Governance Kernel.

Talks directly to the ICEBOX REST API — no native build required.
"""

import json
import urllib.error
import urllib.request
from typing import Any


class IceboxError(Exception):
    pass


class IceboxClient:
    """High-level client for the ICEBOX REST API."""

    def __init__(self, url: str = "http://127.0.0.1:8443"):
        self._base = url.rstrip("/")

    def _get(self, path: str, params: dict | None = None) -> Any:
        url = self._base + path
        if params:
            query = "&".join(f"{k}={v}" for k, v in params.items())
            url = f"{url}?{query}"
        with urllib.request.urlopen(url, timeout=10) as r:
            return json.loads(r.read())

    def _post(self, path: str, body: Any = None) -> Any:
        data = json.dumps(body).encode() if body is not None else b""
        req = urllib.request.Request(
            self._base + path,
            data=data,
            headers={"Content-Type": "application/json"},
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

    def run_module(
        self,
        name: str,
        target: str,
        sandbox: bool = False,
        approved: bool = False,
        options: dict | None = None,
    ) -> dict:
        return self._post(
            f"/api/v1/modules/{name}/run",
            {
                "target": target,
                "sandbox": sandbox,
                "approved": approved,
                "options": options or {},
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


class Governance:
    """Backward-compatible shim — now backed by HTTP instead of ctypes."""

    def __init__(self, config: dict):
        url = config.get("url", "http://127.0.0.1:8443")
        self._client = IceboxClient(url)

    def check(self, task: dict) -> dict:
        name = task.get("module", "")
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
        try:
            raw = urllib.request.urlopen(
                self._client._base + "/api/v1/audit/export", timeout=10
            ).read()
            return raw.decode()
        except Exception:
            return ""
