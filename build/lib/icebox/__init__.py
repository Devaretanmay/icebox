"""Python SDK for the ICEBOX Governance Kernel.

``pip install icebox-sdk`` gives you :class:`Workspace` for high-level
orchestration, and :class:`IceboxClient` for talking to the REST API.
"""

from ._sdk import Governance, IceboxClient, IceboxError

class Workspace:
    """High-level abstraction for ICEBOX orchestration.
    
    Wraps the ICEBOX engine so AI agents don't have to deal with raw
    C-pointers or HTTP endpoints directly.
    """

    def __init__(self, target: str, mode: str = "freezer", url: str = "http://127.0.0.1:8443"):
        """Initialize the workspace with a target path, restriction mode, and ICEBOX daemon URL."""
        self.target = target
        self.mode = mode
        self.client = IceboxClient(url)
        self.client.accept_charter(self.target)
        self.client.add_scope(self.target)
        self.client.set_mode(self.mode)
    
    def execute(self, module: str, sandbox: bool = False, approved: bool = True, options: dict | None = None) -> dict:
        """Executes a module against the workspace target."""
        return self.client.run_module(module, self.target, sandbox=sandbox, approved=approved, options=options)

    def audit(self, n: int = 20) -> list[dict]:
        """Retrieves the JSON audit trail for the workspace."""
        return self.client.audit(n)

__all__ = ["Governance", "IceboxClient", "IceboxError", "Workspace"]
__version__ = "0.2.2"
