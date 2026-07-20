"""ICEBOX v2 — the Session.

An ICEBOX Session is a temporary, isolated staging environment for an
autonomous workflow. The agent enters the Session, runs its whole workflow
inside, and may fail as many times as it wants. Only the first success ever
touches reality — ICEBOX never mutates reality itself; the agent applies the
results.

The Session owns exactly three things:

    enter   -> provision an isolated environment
    execute -> run the agent's workflow (Python callable / CLI command group)
    exit    -> tear down, return artifacts + final status

Everything else (governance, network policy, resource limits) is an optional
plugin mounted on the Session. Audit is built in: every Session records its
own execution history as a fundamental part of the product.
"""

from __future__ import annotations

import abc
import json
import os
import shutil
import subprocess
import time
import traceback
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional


IMAGE = os.environ.get("ICEBOX_IMAGE", "python:3.12-slim")
DOCKER = "docker"


# ---------------------------------------------------------------------------
# Audit — built in to every Session.
# ---------------------------------------------------------------------------
@dataclass
class Attempt:
    index: int
    command: str
    exit_code: int
    stdout: str
    stderr: str
    started_at: float
    duration_s: float
    error: Optional[str] = None


@dataclass
class SessionAudit:
    """Workflow artifacts and execution history for one Session.

    This is not governance. It is a factual record of what the agent tried,
    how many times it failed, and what came out.
    """

    session_id: str
    task: str = ""
    attempts: list[Attempt] = field(default_factory=list)
    artifacts: dict[str, Any] = field(default_factory=dict)
    status: str = "running"  # running | success | failed

    def record(self, attempt: Attempt) -> None:
        self.attempts.append(attempt)

    @property
    def failures(self) -> int:
        return sum(1 for a in self.attempts if a.exit_code != 0)

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "task": self.task,
            "status": self.status,
            "attempts": len(self.attempts),
            "failures": self.failures,
            "duration_s": round(sum(a.duration_s for a in self.attempts), 2),
            "artifacts": self.artifacts,
            "history": [
                {
                    "index": a.index,
                    "command": a.command,
                    "exit_code": a.exit_code,
                    "duration_s": round(a.duration_s, 2),
                    "error": a.error,
                }
                for a in self.attempts
            ],
        }


# ---------------------------------------------------------------------------
# Plugins — optional concerns mounted on a Session.
# ---------------------------------------------------------------------------
class SessionPlugin(abc.ABC):
    """Optional behavior a Session can opt into.

    Governance, network policy, and resource limits are plugins. Audit is NOT
    a plugin — it is always on.
    """

    name: str = "plugin"

    def on_enter(self, session: "Session") -> None:
        ...

    def on_exit(self, session: "Session") -> None:
        ...


# ---------------------------------------------------------------------------
# The Session.
# ---------------------------------------------------------------------------
class Session:
    """A temporary isolated staging environment for one autonomous workflow.

    The Session is isolated (Docker by default). The agent runs its workflow
    inside; ICEBOX records what happened. On failure the agent may retry
    inside the same Session as many times as it needs.
    """

    def __init__(
        self,
        task: str = "",
        plugins: Optional[list[SessionPlugin]] = None,
        image: str = IMAGE,
        lifetime_s: Optional[int] = None,
        workdir: Optional[str] = None,
        max_attempts: int = 100_000,
    ) -> None:
        self.session_id = f"icebox-{uuid.uuid4().hex[:8]}"
        self.task = task
        self.plugins = plugins or []
        self.image = image
        self.lifetime_s = lifetime_s
        self.workdir = workdir
        self.max_attempts = max_attempts
        self.audit = SessionAudit(session_id=self.session_id, task=task)
        self._container: Optional[str] = None
        self._entered = False

    # -- lifecycle ---------------------------------------------------------
    def enter(self) -> "Session":
        if not shutil.which(DOCKER):
            raise RuntimeError(
                "Docker is required for an ICEBOX Session but was not found "
                "on PATH. Install Docker or set ICEBOX_IMAGE to a local runner."
            )
        container = subprocess.run(
            [
                DOCKER, "run", "-d", "--rm",
                "-e", "ICEBOX_SESSION=1",
                self.image, "sleep", "infinity",
            ],
            capture_output=True, text=True, check=True,
        )
        self._container = container.stdout.strip()
        self._entered = True
        for p in self.plugins:
            p.on_enter(self)
        return self

    def exit(self) -> SessionAudit:
        if self._container:
            subprocess.run([DOCKER, "rm", "-f", self._container],
                           capture_output=True, text=True)
            self._container = None
        for p in self.plugins:
            p.on_exit(self)
        if self.audit.status == "running":
            self.audit.status = "failed"
        return self.audit

    # -- execution ---------------------------------------------------------
    def run(
        self,
        target: Callable[[], Any] | str,
        validate: Optional[Callable[[SessionAudit], bool]] = None,
        *,
        cwd: Optional[str] = None,
        env: Optional[dict] = None,
    ) -> SessionAudit:
        """Run ``target`` inside the Session, retrying until success.

        ``target`` is either a Python callable or a CLI command group (str).
        The default success gate is "exited 0"; pass ``validate`` to require a
        richer condition. On failure the agent refactors and re-runs inside the
        same Session — reality never sees the failures.

        Returns the Session audit (attempts, failures, artifacts, status).
        """
        if not self._entered:
            self.enter()
        attempt = 0
        while attempt < self.max_attempts:
            attempt += 1
            started = time.time()
            cmd, exit_code, out, err, err_msg = self._execute_once(
                target, attempt, cwd, env
            )
            self.audit.record(Attempt(
                index=attempt, command=cmd, exit_code=exit_code,
                stdout=out, stderr=err, started_at=started,
                duration_s=time.time() - started, error=err_msg,
            ))
            if exit_code == 0 and (validate is None or validate(self.audit)):
                self.audit.status = "success"
                self.audit.artifacts.setdefault(
                    "last_stdout", out
                )
                return self.exit()
            # failure: stay inside the Session, let the agent refactor + retry
            time.sleep(0)  # cooperative yield; real agents redo work in-process
        self.audit.status = "failed"
        return self.exit()

    def run_cli(self, command: str, **kwargs) -> SessionAudit:
        """Convenience: run a CLI command group inside the Session."""
        return self.run(command, **kwargs)

    def _execute_once(self, target, attempt: int, cwd, env):
        if callable(target) and not isinstance(target, str):
            return self._execute_callable(target)
        return self._execute_cli(str(target), cwd, env)

    def _execute_callable(self, fn: Callable[[], Any]):
        if not self._container:
            raise RuntimeError("Session not entered")
        # Serialize the callable's source and run it inside the container via
        # Python. The agent's own runtime lives in the Session. The callable
        # must be defined in a real .py file (REPL/lambda sources can't be
        # retrieved); for those, use run_cli() with a command group instead.
        import inspect
        mod = inspect.getmodule(fn)
        if mod is None:
            mod = sys.modules.get(getattr(fn, "__module__", ""))
        if mod is None or mod is inspect.getmodule(inspect):
            raise RuntimeError(
                "ICEBOX could not read the callable's module. Define the "
                "workflow in a .py file, or use run_cli('python your_agent.py') "
                "for workflows defined inline."
            )
        try:
            module_source = inspect.getsource(mod)
        except OSError:
            raise RuntimeError(
                "ICEBOX could not read the callable's source. Define the "
                "workflow in a .py file, or use run_cli('python your_agent.py') "
                "for workflows defined inline."
            )
        payload = {
            "source": module_source,
            "name": getattr(fn, "__name__", "target"),
        }
        # Run the whole module in-container (so its imports resolve), then call
        # the named callable. This mirrors how the agent actually runs locally.
        script = (
            "import json,sys\n"
            "p=json.loads(sys.stdin.read())\n"
            "ns={}\n"
            "exec(p['source'], ns)\n"
            "fn=ns.get(p['name'])\n"
            "fn() if callable(fn) else None\n"
        )
        proc = subprocess.run(
            [DOCKER, "exec", "-i", self._container, "python3", "-c", script],
            input=json.dumps(payload), capture_output=True, text=True, timeout=3600,
        )
        return (f"python:{getattr(fn,'__name__','target')}",
                proc.returncode, proc.stdout, proc.stderr,
                proc.stderr if proc.returncode != 0 else None)

    def _execute_cli(self, command: str, cwd, env):
        if not self._container:
            raise RuntimeError("Session not entered")
        proc = subprocess.run(
            [DOCKER, "exec", self._container, "sh", "-c", command],
            capture_output=True, text=True, cwd=cwd,
            env={**os.environ, **(env or {})}, timeout=3600,
        )
        return (command, proc.returncode, proc.stdout, proc.stderr,
                proc.stderr if proc.returncode != 0 else None)

    # -- context manager ---------------------------------------------------
    def __enter__(self) -> "Session":
        return self.enter()

    def __exit__(self, exc_type, exc, tb) -> bool:
        self.exit()
        return False

    def __repr__(self) -> str:
        return f"<Session {self.session_id} task={self.task!r}>"


def icebox(
    task: str = "",
    *,
    plugins: Optional[list[SessionPlugin]] = None,
    profile: Optional[str] = None,
    image: str = IMAGE,
    lifetime_s: Optional[int] = None,
    max_attempts: int = 100_000,
) -> Session:
    """Create an ICEBOX Session.

    By default this is pure isolated iterative staging: audit is on, no
    governance. Add ``plugins=[Governance(), NetworkPolicy()]`` for more, or
    select a named ``profile`` (e.g. "aws", "pentesting") that bundles them.
    """
    if profile:
        plugins = _resolve_profile(profile, plugins)
    return Session(
        task=task, plugins=plugins, image=image,
        lifetime_s=lifetime_s, max_attempts=max_attempts,
    )


_PROFILES: dict[str, list[SessionPlugin]] = {}


def _resolve_profile(name: str, extra) -> list[SessionPlugin]:
    base = list(_PROFILES.get(name, []))
    if extra:
        base.extend(extra)
    return base


def register_profile(name: str, plugins: list[SessionPlugin]) -> None:
    """Register a named profile (a bundle of plugins) for ``icebox(profile=)``."""
    _PROFILES[name] = plugins
