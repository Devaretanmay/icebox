# SDK: C ABI

The `libicebox` shared library is the lowest-level integration surface.
It is what the Rust and Python SDKs wrap, and you can call it
directly from any FFI-capable language.

## Functions

| Symbol | Signature | Purpose |
| --- | --- | --- |
| `icebox_govern` | `extern "C" icebox_govern(*const c_char) -> *mut c_void` | Build a `GovernanceRuntime` from a JSON config. Returns an opaque handle. |
| `icebox_check` | `icebox_check(handle, *const c_char) -> *mut c_char` | Supervised evaluation of a JSON task. Returns a JSON outcome. |
| `icebox_check_auto` | `icebox_check_auto(handle, *const c_char) -> *mut c_char` | Unsupervised evaluation; approval-gated tasks auto-granted. |
| `icebox_approve` | `icebox_approve(handle, u64) -> bool` | Approve a pending request by id. |
| `icebox_deny` | `icebox_deny(handle, u64) -> bool` | Deny a pending request by id. |
| `icebox_pending` | `icebox_pending(handle) -> *mut c_char` | JSON list of pending approval requests. |
| `icebox_audit_json` | `icebox_audit_json(handle) -> *mut c_char` | Full audit trail as JSON. |
| `icebox_audit_csv` | `icebox_audit_csv(handle) -> *mut c_char` | Full audit trail as CSV. |
| `icebox_free_string` | `icebox_free_string(*mut c_void)` | Free a string returned by the API. |
| `icebox_free_handle` | `icebox_free_handle(*mut c_void)` | Free a runtime handle. |

All returned `*mut c_char` strings are owned by the caller and must be
freed with `icebox_free_string`.

## Build the library

```sh
cargo build --release     # -> target/release/libicebox.{so,dylib,dll}
```

## Config / task shape

```json
{ "charter": "authorized engagement",
  "scope": ["10.0.0.0/24"],
  "max_risk": "high" }
```

```json
{ "module": "tcp_port_scanner",
  "target": "10.0.0.5",
  "options": { "host": "10.0.0.5", "ports": "1-1024" } }
```
