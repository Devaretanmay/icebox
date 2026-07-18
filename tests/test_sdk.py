"""Unit tests for the ICEBOX Python SDK (HTTP transport).

Spins up a real in-process HTTP server so no ICEBOX daemon is required.
"""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "python"))

from icebox import IceboxClient, IceboxError
from icebox.tools import openai_tools, dispatch_tool_call


MODULES = [
    {"name": "mysql_scanner", "kind": "scanner", "description": "MySQL scanner"},
    {"name": "vuln_scanner",  "kind": "analysis", "description": "Dep vuln scanner"},
]

MODULE_DETAIL = {
    "name": "mysql_scanner",
    "kind": "scanner",
    "description": "MySQL scanner",
    "author": "ICEBOX",
    "options": {"host": "", "port": 3306, "check_defaults": False},
    "target": None,
    "in_scope": None,
    "charter_accepted": False,
}

APPROVALS = [
    {"id": 1, "module": "mysql_scanner", "target": "10.0.0.1", "reason": "destructive", "status": "Pending"},
]

RUN_RESULT = {"job_id": 42, "success": True, "data": {}, "preflight": None, "error": None}
AUDIT = [{"at": 1000, "target": "10.0.0.1", "module": "mysql_scanner", "decision": "Allow"}]


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def _respond(self, body, status=200):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(data))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        routes = {
            "/api/v1/modules": MODULES,
            "/api/v1/modules/mysql_scanner": MODULE_DETAIL,
            "/api/v1/approvals": APPROVALS,
            "/api/v1/audit": AUDIT,
        }
        path = self.path.split("?")[0]
        if path in routes:
            self._respond(routes[path])
        else:
            self._respond({"error": "not found"}, 404)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        if self.path == "/api/v1/modules/mysql_scanner/run":
            self._respond(RUN_RESULT)
        elif self.path == "/api/v1/govern":
            self._respond({"approved": True, "decision": "allow", "decision_id": 1, "chain_tip": "abc"})
        elif self.path == "/api/v1/govern/record":
            self._respond({"decision_id": 1, "chain_tip": "def"})
        elif "/approve" in self.path:
            self._respond("approved")
        elif "/deny" in self.path:
            self._respond("denied")
        else:
            self._respond({"error": "not found"}, 404)


@pytest.fixture(scope="module")
def client():
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield IceboxClient(f"http://127.0.0.1:{port}")
    server.shutdown()


def test_list_modules(client):
    mods = client.list_modules()
    assert len(mods) == 2
    assert mods[0]["name"] == "mysql_scanner"


def test_get_module(client):
    detail = client.get_module("mysql_scanner")
    assert detail["author"] == "ICEBOX"
    assert "options" in detail


def test_run_module(client):
    result = client.run_module("mysql_scanner", target="10.0.0.1")
    assert result["job_id"] == 42
    assert result["success"] is True


def test_pending_approvals(client):
    pending = client.pending_approvals()
    assert len(pending) == 1
    assert pending[0]["id"] == 1


def test_approve(client):
    resp = client.approve(1)
    assert resp == "approved"


def test_deny(client):
    resp = client.deny(1)
    assert resp == "denied"


def test_audit(client):
    records = client.audit(n=5)
    assert len(records) == 1
    assert records[0]["module"] == "mysql_scanner"


def test_openai_tools_schema(client):
    tools = openai_tools(client)
    assert len(tools) == 2
    mysql = next(t for t in tools if t["function"]["name"] == "icebox_mysql_scanner")
    params = mysql["function"]["parameters"]
    assert params["type"] == "object"
    assert "target" in params["properties"]
    assert "target" in params["required"]
    assert mysql["type"] == "function"


def test_openai_tool_schema_types(client):
    tools = openai_tools(client)
    mysql = next(t for t in tools if t["function"]["name"] == "icebox_mysql_scanner")
    props = mysql["function"]["parameters"]["properties"]
    assert props["port"]["type"] == "integer"
    assert props["check_defaults"]["type"] == "boolean"


def test_dispatch_tool_call(client):
    result = dispatch_tool_call(
        client, "icebox_mysql_scanner", {"target": "10.0.0.1"}
    )
    assert result["job_id"] == 42


def test_dispatch_tool_call_bad_name(client):
    with pytest.raises(ValueError, match="Not an ICEBOX tool"):
        dispatch_tool_call(client, "something_else", {"target": "x"})


def test_governance_compat(client):
    from icebox import Governance
    gov = Governance({"url": client._base})
    assert isinstance(gov.pending(), list)
    assert isinstance(gov.audit_json(), list)


def test_govern_context_manager(client):
    from icebox import govern

    with govern(url=client._base) as g:
        verdict = g.preflight({
            "action": "scan",
            "target": "10.0.0.5",
            "capability": "network_scan",
            "impact": "low",
            "destructive": False,
        })
        assert verdict["approved"] is True
        recorded = g.complete({"success": True, "evidence": [], "data": {}},
                              verdict.get("decision", "allow"))
        assert "chain_tip" in recorded
