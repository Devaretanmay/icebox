"""ICEBOX — a staging environment for autonomous workflows.

The only thing most people need:

    from icebox import icebox

    with icebox() as session:
        session.run(my_agent.run_task)

ICEBOX gives an AI agent a temporary, isolated place to run its whole
workflow and fail as many times as it wants. Reality only ever sees the
first success. ICEBOX never mutates reality itself.

The legacy governance SDK (``govern``, ``Workspace``) is still importable
from :mod:`icebox.governance` for v1 users and is being relocated to an
optional plugin.
"""

from .session import Session, SessionPlugin, SessionAudit, icebox, register_profile
from . import governance  # noqa: F401  (v1 governance, optional plugin)

# v1 governance surface (deprecated, relocated to icebox.governance)
from ._sdk import (  # noqa: F401
    GovernClient,
    Governance,
    IceboxClient,
    IceboxError,
    GovernedSession,
    GovernResult,
    govern,
)

__all__ = [
    "Session", "SessionPlugin", "SessionAudit", "icebox", "register_profile",
    "governance",
    "govern", "Governance", "GovernClient", "IceboxClient", "IceboxError",
    "GovernedSession", "GovernResult",
]
__version__ = "2.0.0b0"
