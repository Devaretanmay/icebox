"""ICEBOX v1 governance, preserved as an OPTIONAL plugin.

In v2 the governance kernel is not on by default. Agents that want the old
"is this action allowed?" gating mount it explicitly:

    from icebox import icebox
    from icebox.governance import Governance

    with icebox(plugins=[Governance()]) as s:
        s.run(my_agent.run_task)

The reusable primitives (``govern``, ``IceboxClient``, ``Governance``) are
re-exported here so v1 users keep importing them unchanged.
"""

from ._sdk import (  # noqa: F401
    GovernClient,
    Governance as GovernanceClient,
    IceboxClient,
    IceboxError,
    GovernedSession,
    GovernResult,
    govern,
)
from .session import SessionPlugin


class Governance(SessionPlugin):
    """Optional governance gate mounted on a Session.

    When mounted, the plugin records that governance is active for the
    Session. The actual allow/deny decisions live in the ``govern()`` API
    the agent calls inside the workflow — ICEBOX v2 does not force them.
    """

    name = "governance"

    def __init__(self, profile: str | None = None, url: str = "http://127.0.0.1:8443"):
        self.profile = profile
        self.url = url

    def on_enter(self, session) -> None:
        session.audit.artifacts.setdefault("governance", self.profile or "enabled")

    def on_exit(self, session) -> None:
        ...
