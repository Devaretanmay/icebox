"""Python SDK for the ICEBOX Governance Kernel.

``pip install icebox-sdk`` gives you :class:`IceboxClient` for talking to
the ICEBOX REST API and :class:`Governance` for backward-compatible usage.
"""

from ._sdk import Governance, IceboxClient, IceboxError

__all__ = ["Governance", "IceboxClient", "IceboxError"]
__version__ = "0.2.0"
