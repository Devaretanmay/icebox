"""Python SDK for the ICEBOX Governance Kernel.

``pip install icebox-sdk`` gives you :class:`Workspace` for high-level
orchestration, and :class:`IceboxClient` for talking to the REST API.
"""

from ._sdk import GovernClient, Governance, IceboxClient, IceboxError

import contextlib

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
    
    def execute(self, module: str, approved: bool = True, options: dict | None = None) -> dict:
        """Executes a module against the workspace target."""
        return self.client.run_module(module, self.target, approved=approved, options=options)

    def audit(self, n: int = 20) -> list[dict]:
        """Retrieves the JSON audit trail for the workspace."""
        return self.client.audit(n)

    @contextlib.contextmanager
    def tunnel(self, port: int):
        """Creates a governed tunnel to the target port.
        
        Yields a local port that the agent can connect to. ICEBOX will intercept,
        govern, and forward the traffic to the real target.
        """
        res = self.client.bind_proxy(self.target, port)
        if "error" in res and res["error"]:
            raise IceboxError(f"Failed to bind proxy: {res['error']}")
        local_port = res.get("local_port")
        if not local_port:
            raise IceboxError(f"No local port returned: {res}")
        try:
            yield local_port
        finally:
            self.client.unbind_proxy(local_port)

__all__ = ["Governance", "GovernClient", "IceboxClient", "IceboxError", "Workspace"]
__version__ = "0.2.3"
