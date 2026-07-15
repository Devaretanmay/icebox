//! C ABI for the ICEBOX Governance SDK.

#![allow(clippy::missing_safety_doc)]

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_void};

use icebox_core::sdk::{govern, GovernanceConfig, GovernanceRuntime, TaskSpec};
use serde_json::json;

fn runtime(handle: *mut c_void) -> Option<&'static GovernanceRuntime> {
    if handle.is_null() {
        return None;
    }
    unsafe { (handle as *mut GovernanceRuntime).as_ref() }
}

fn to_cstring(s: String) -> *mut c_char {
    CString::new(s).unwrap_or_else(|_| CString::new("").unwrap()).into_raw()
}

fn tokio_rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
}

#[no_mangle]
pub unsafe extern "C" fn icebox_govern(config_json: *const c_char) -> *mut c_void {
    let cfg_str = match unsafe { CStr::from_ptr(config_json) }.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    let cfg: GovernanceConfig = match serde_json::from_str(cfg_str) {
        Ok(c) => c,
        Err(_) => return std::ptr::null_mut(),
    };
    Box::into_raw(Box::new(govern(cfg))) as *mut c_void
}

#[no_mangle]
pub unsafe extern "C" fn icebox_check(handle: *mut c_void, task_json: *const c_char) -> *mut c_char {
    check_task(handle, task_json, false)
}

#[no_mangle]
pub unsafe extern "C" fn icebox_check_auto(handle: *mut c_void, task_json: *const c_char) -> *mut c_char {
    check_task(handle, task_json, true)
}

unsafe fn check_task(handle: *mut c_void, task_json: *const c_char, auto: bool) -> *mut c_char {
    let gov = match runtime(handle) {
        Some(r) => r,
        None => return to_cstring(json!({"error": "invalid handle"}).to_string()),
    };
    let task_str = match unsafe { CStr::from_ptr(task_json) }.to_str() {
        Ok(s) => s,
        Err(_) => return to_cstring(json!({"error": "invalid task json"}).to_string()),
    };
    let task: TaskSpec = match serde_json::from_str(task_str) {
        Ok(t) => t,
        Err(e) => return to_cstring(json!({"error": e.to_string()}).to_string()),
    };
    let rt = tokio_rt();
    let outcome = if auto {
        rt.block_on(gov.run(task, || async { Ok(json!(null)) }))
    } else {
        rt.block_on(gov.execute(task, || async { Ok(json!(null)) }))
    };
    to_cstring(serde_json::to_string(&outcome).unwrap_or_else(|_| "{}".into()))
}

#[no_mangle]
pub extern "C" fn icebox_approve(handle: *mut c_void, id: u64) -> bool {
    match runtime(handle) {
        Some(gov) => {
            let rt = tokio_rt();
            rt.block_on(gov.approve(id))
        }
        None => false,
    }
}

#[no_mangle]
pub extern "C" fn icebox_deny(handle: *mut c_void, id: u64) -> bool {
    match runtime(handle) {
        Some(gov) => {
            let rt = tokio_rt();
            rt.block_on(gov.deny(id))
        }
        None => false,
    }
}

#[no_mangle]
pub extern "C" fn icebox_pending(handle: *mut c_void) -> *mut c_char {
    match runtime(handle) {
        Some(gov) => {
            let rt = tokio_rt();
            let pending = rt.block_on(gov.pending_approvals());
            to_cstring(serde_json::to_string(&pending).unwrap_or_else(|_| "[]".into()))
        }
        None => to_cstring("[]".into()),
    }
}

#[no_mangle]
pub extern "C" fn icebox_audit_json(handle: *mut c_void) -> *mut c_char {
    match runtime(handle) {
        Some(gov) => {
            let rt = tokio_rt();
            to_cstring(rt.block_on(gov.export_audit_json()))
        }
        None => to_cstring("[]".into()),
    }
}

#[no_mangle]
pub extern "C" fn icebox_audit_csv(handle: *mut c_void) -> *mut c_char {
    match runtime(handle) {
        Some(gov) => {
            let rt = tokio_rt();
            to_cstring(rt.block_on(gov.export_audit_csv()))
        }
        None => to_cstring(String::new()),
    }
}

#[no_mangle]
pub unsafe extern "C" fn icebox_free_handle(handle: *mut c_void) {
    if !handle.is_null() {
        drop(Box::from_raw(handle as *mut GovernanceRuntime));
    }
}

#[no_mangle]
pub unsafe extern "C" fn icebox_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        drop(CString::from_raw(ptr));
    }
}
