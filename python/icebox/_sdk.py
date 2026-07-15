"""ctypes wrapper around the ICEBOX ``libicebox`` C ABI."""

import ctypes
import glob
import json
import os

# Loads libicebox from a wheel build, a cargo target dir, or ICEBOX_CAPI.
_PKG_DIR = os.path.dirname(os.path.abspath(__file__))
_NATIVE = next(
    iter(glob.glob(os.path.join(_PKG_DIR, "_native.*"))), None
)
_CANDIDATES = [
    _NATIVE,
    "target/debug/libicebox.dylib",
    "target/debug/libicebox.so",
    "target/release/libicebox.dylib",
    "target/release/libicebox.so",
    "libicebox.dylib",
    "libicebox.so",
    "icebox.dll",
    os.environ.get("ICEBOX_CAPI", ""),
]


def _load_lib():
    for path in _CANDIDATES:
        if not path:
            continue
        try:
            return ctypes.CDLL(path)
        except OSError:
            continue
    raise RuntimeError(
        "libicebox not found. Build it with `cargo build` "
        "or set ICEBOX_CAPI to the shared library path."
    )


_lib = _load_lib()

_lib.icebox_govern.restype = ctypes.c_void_p
_lib.icebox_govern.argtypes = [ctypes.c_char_p]

_lib.icebox_check.restype = ctypes.c_void_p
_lib.icebox_check.argtypes = [ctypes.c_void_p, ctypes.c_char_p]

_lib.icebox_check_auto.restype = ctypes.c_void_p
_lib.icebox_check_auto.argtypes = [ctypes.c_void_p, ctypes.c_char_p]

_lib.icebox_approve.restype = ctypes.c_bool
_lib.icebox_approve.argtypes = [ctypes.c_void_p, ctypes.c_uint64]

_lib.icebox_deny.restype = ctypes.c_bool
_lib.icebox_deny.argtypes = [ctypes.c_void_p, ctypes.c_uint64]

_lib.icebox_pending.restype = ctypes.c_void_p
_lib.icebox_pending.argtypes = [ctypes.c_void_p]

_lib.icebox_audit_json.restype = ctypes.c_void_p
_lib.icebox_audit_json.argtypes = [ctypes.c_void_p]

_lib.icebox_audit_csv.restype = ctypes.c_void_p
_lib.icebox_audit_csv.argtypes = [ctypes.c_void_p]

_lib.icebox_free_string.argtypes = [ctypes.c_void_p]

_lib.icebox_free_handle.argtypes = [ctypes.c_void_p]


def _read_string(ptr):
    if not ptr:
        return None
    data = ctypes.c_char_p(ptr).value
    _lib.icebox_free_string(ptr)
    return data.decode() if data is not None else None


class Governance:
    def __init__(self, config: dict):
        cfg = json.dumps(config).encode()
        self.handle = _lib.icebox_govern(cfg)
        if not self.handle:
            raise ValueError("icebox_govern failed: invalid config")

    def check(self, task: dict) -> dict:
        raw = _read_string(_lib.icebox_check(self.handle, json.dumps(task).encode()))
        return json.loads(raw) if raw else {}

    def run(self, task: dict) -> dict:
        raw = _read_string(_lib.icebox_check_auto(self.handle, json.dumps(task).encode()))
        return json.loads(raw) if raw else {}

    def approve(self, approval_id: int) -> bool:
        return bool(_lib.icebox_approve(self.handle, approval_id))

    def deny(self, approval_id: int) -> bool:
        return bool(_lib.icebox_deny(self.handle, approval_id))

    def pending(self) -> list:
        raw = _read_string(_lib.icebox_pending(self.handle))
        return json.loads(raw) if raw else []

    def audit_json(self) -> list:
        raw = _read_string(_lib.icebox_audit_json(self.handle))
        return json.loads(raw) if raw else []

    def audit_csv(self) -> str:
        raw = _read_string(_lib.icebox_audit_csv(self.handle))
        return raw or ""

    def __del__(self):
        if getattr(self, "handle", None):
            _lib.icebox_free_handle(self.handle)
            self.handle = None
