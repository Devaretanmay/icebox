#![allow(clippy::missing_safety_doc)]

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_void};

use crate::core::sdk::{govern, GovernanceConfig, GovernanceRuntime, TaskSpec};
use serde_json::json;

fn runtime(handle: *mut c_void) -> Option<&'static GovernanceRuntime> {
    if handle.is_null() {
        return None;
    }
    unsafe { (handle as *mut GovernanceRuntime).as_ref() }
}

fn to_cstring(s: String) -> *mut c_char {
    CString::new(s)
        .unwrap_or_else(|_| CString::new("<invalid>").unwrap())
        .into_raw()
}

fn tokio_rt() -> Option<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .ok()
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
pub unsafe extern "C" fn icebox_check(
    handle: *mut c_void,
    task_json: *const c_char,
) -> *mut c_char {
    check_task(handle, task_json, false)
}

#[no_mangle]
pub unsafe extern "C" fn icebox_check_auto(
    handle: *mut c_void,
    task_json: *const c_char,
) -> *mut c_char {
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
    let Some(rt) = tokio_rt() else {
        return to_cstring(json!({"error": "failed to create tokio runtime"}).to_string());
    };
    let name = task.name.clone();
    let target = task.target.clone();
    let options = task.options.clone();
    let action = move || {
        let name = name.clone();
        let target = target.clone();
        let options = options.clone();
        async move {
            match gov.execute_module(&name, &target, &options).await {
                Ok(s) => Ok(serde_json::Value::String(s)),
                Err(e) => Err(e),
            }
        }
    };
    let outcome = if auto {
        rt.block_on(gov.run(task, action))
    } else {
        rt.block_on(gov.execute(task, action))
    };
    to_cstring(serde_json::to_string(&outcome).unwrap_or_else(|_| "{}".into()))
}

#[no_mangle]
pub extern "C" fn icebox_approve(handle: *mut c_void, id: u64) -> bool {
    let gov = match runtime(handle) {
        Some(g) => g,
        None => return false,
    };
    let Some(rt) = tokio_rt() else { return false };
    rt.block_on(gov.approve(id))
}

#[no_mangle]
pub extern "C" fn icebox_deny(handle: *mut c_void, id: u64) -> bool {
    let gov = match runtime(handle) {
        Some(g) => g,
        None => return false,
    };
    let Some(rt) = tokio_rt() else { return false };
    rt.block_on(gov.deny(id))
}

#[no_mangle]
pub extern "C" fn icebox_pending(handle: *mut c_void) -> *mut c_char {
    let gov = match runtime(handle) {
        Some(g) => g,
        None => return to_cstring("[]".into()),
    };
    let Some(rt) = tokio_rt() else { return to_cstring("[]".into()) };
    let pending = rt.block_on(gov.pending_approvals());
    to_cstring(serde_json::to_string(&pending).unwrap_or_else(|_| "[]".into()))
}

#[no_mangle]
pub extern "C" fn icebox_audit_json(handle: *mut c_void) -> *mut c_char {
    let gov = match runtime(handle) {
        Some(g) => g,
        None => return to_cstring("[]".into()),
    };
    let Some(rt) = tokio_rt() else { return to_cstring("[]".into()) };
    to_cstring(rt.block_on(gov.export_audit_json()))
}

#[no_mangle]
pub extern "C" fn icebox_audit_csv(handle: *mut c_void) -> *mut c_char {
    let gov = match runtime(handle) {
        Some(g) => g,
        None => return to_cstring(String::new()),
    };
    let Some(rt) = tokio_rt() else { return to_cstring(String::new()) };
    to_cstring(rt.block_on(gov.export_audit_csv()))
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
