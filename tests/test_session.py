"""Tests for the ICEBOX v2 Session: isolation, iteration, and audit.

These need a working Docker daemon. They are skipped automatically when Docker
is unavailable (e.g. in minimal CI).
"""

import importlib.util
import subprocess
import sys

import pytest

docker = shutil_which = __import__("shutil").which("docker")
pytestmark = pytest.mark.skipif(
    not docker or subprocess.run([docker, "info"], capture_output=True).returncode != 0,
    reason="Docker daemon not available",
)


def _make_agent(tmp_path, body):
    f = tmp_path / "agent.py"
    f.write_text(body)
    spec = importlib.util.spec_from_file_location("agent", f)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["agent"] = mod
    spec.loader.exec_module(mod)
    return mod


def test_session_runs_cli_command_group():
    from icebox import icebox

    with icebox(task="echo test", max_attempts=3) as s:
        audit = s.run("echo hello-box")
    assert audit.status == "success"
    assert len(audit.attempts) == 1
    assert audit.failures == 0
    assert "hello-box" in (audit.artifacts.get("last_stdout") or "")


def test_session_retries_until_success(tmp_path):
    from icebox import icebox

    # The command fails (non-zero) until a flag file exists, then succeeds.
    # Because the container's filesystem persists across attempts, this models
    # an agent that refactors and retries inside the same Session.
    cmd = "if test -f /tmp/done; then echo SUCCESS; else touch /tmp/done; exit 3; fi"
    with icebox(task="retry until done", max_attempts=5) as s:
        audit = s.run(cmd)
    assert audit.status == "success"
    assert audit.failures >= 1  # at least one non-zero exit happened


def test_session_records_audit_history():
    from icebox import icebox

    with icebox(task="history", max_attempts=3) as s:
        audit = s.run("echo artifact-output")
    d = audit.to_dict()
    assert d["session_id"].startswith("icebox-")
    assert d["status"] == "success"
    assert d["attempts"] == 1
    assert d["failures"] == 0
    assert "artifact-output" in d["artifacts"]["last_stdout"]


def test_session_failure_respects_max_attempts():
    from icebox import icebox

    with icebox(task="always fail", max_attempts=3) as s:
        audit = s.run("exit 1")
    assert audit.status == "failed"
    assert len(audit.attempts) == 3
    assert audit.failures == 3


def test_session_runs_python_callable(tmp_path):
    from icebox import icebox

    mod = _make_agent(tmp_path, "def run():\n    print('inside the box')\n")
    with icebox(task="py callable", max_attempts=3) as s:
        audit = s.run(mod.run)
    assert audit.status == "success"
    assert "inside the box" in (audit.artifacts.get("last_stdout") or "")


def test_validate_callback_is_optional_default_exit_zero():
    from icebox import icebox

    # No validate => success is simply exit 0.
    with icebox(task="default validate", max_attempts=3) as s:
        audit = s.run("true")
    assert audit.status == "success"


def test_container_is_destroyed_on_exit():
    from icebox import icebox

    s = icebox(task="teardown check", max_attempts=3)
    s.enter()
    cid = s._container
    assert cid
    running = subprocess.run(
        [docker, "inspect", "-f", "{{.State.Running}}", cid],
        capture_output=True, text=True,
    ).stdout.strip() == "true"
    assert running
    s.exit()
    gone = subprocess.run(
        [docker, "inspect", cid], capture_output=True,
    ).returncode != 0
    assert gone
