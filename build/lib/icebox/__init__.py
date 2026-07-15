"""Python SDK for the ICEBOX Governance Kernel (C ABI / ctypes).

``pip install icebox-sdk`` gives you :class:`icebox.Governance`, which drives
the same charter / scope / risk / approval gates that guard native ICEBOX
modules — so any Python agent can be governed by the single seam.
"""

from ._sdk import Governance

__all__ = ["Governance"]
__version__ = "0.1.0"
