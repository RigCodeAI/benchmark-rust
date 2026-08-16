use std::convert::Infallible;
use std::ffi::CString;

use axum::{extract::Query, routing::get, Router};
use serde::Deserialize;

use crate::ApplicationState;

const MEMORY_BOUND: usize = 8;

#[derive(Deserialize)]
struct RustSpecificInput {
    value: String,
}

pub(crate) fn routes() -> Router<ApplicationState> {
    Router::new()
        .route("/cwe-119/vulnerable", get(cwe_119_vulnerable))
        .route("/cwe-119/safe", get(cwe_119_safe))
        .route("/cwe-119/unknown", get(cwe_119_unknown))
        .route("/cwe-125/vulnerable", get(cwe_125_vulnerable))
        .route("/cwe-125/safe", get(cwe_125_safe))
        .route("/cwe-125/unknown", get(cwe_125_unknown))
        .route("/cwe-416/vulnerable", get(cwe_416_vulnerable))
        .route("/cwe-416/safe", get(cwe_416_safe))
        .route("/cwe-416/unknown", get(cwe_416_unknown))
        .route("/cwe-787/vulnerable", get(cwe_787_vulnerable))
        .route("/cwe-787/safe", get(cwe_787_safe))
        .route("/cwe-787/unknown", get(cwe_787_unknown))
        .route("/unsafe/vulnerable", get(unsafe_vulnerable))
        .route("/unsafe/safe", get(unsafe_safe))
        .route("/unsafe/unknown", get(unsafe_unknown))
        .route("/ffi/vulnerable", get(ffi_vulnerable))
        .route("/ffi/safe", get(ffi_safe))
        .route("/ffi/unknown", get(ffi_unknown))
        .route("/panic/vulnerable", get(panic_vulnerable))
        .route("/panic/safe", get(panic_safe))
        .route("/panic/unknown", get(panic_unknown))
}

async fn cwe_119_vulnerable(Query(input): Query<RustSpecificInput>) -> &'static str {
    let _ = generic_memory_unchecked(&input.value);
    "ok"
}

async fn cwe_119_safe(Query(input): Query<RustSpecificInput>) -> &'static str {
    let _ = generic_memory_checked(&input.value);
    "ok"
}

async fn cwe_119_unknown(Query(input): Query<RustSpecificInput>) -> &'static str {
    ambiguous::memory_generic(&input.value);
    "ok"
}

async fn cwe_125_vulnerable(Query(input): Query<RustSpecificInput>) -> &'static str {
    let _ = out_of_bounds_read_intercepted(&input.value);
    "ok"
}

async fn cwe_125_safe(Query(input): Query<RustSpecificInput>) -> &'static str {
    let _ = bounds_checked_read(&input.value);
    "ok"
}

async fn cwe_125_unknown(Query(input): Query<RustSpecificInput>) -> &'static str {
    ambiguous::memory_read(&input.value);
    "ok"
}

async fn cwe_416_vulnerable(Query(input): Query<RustSpecificInput>) -> &'static str {
    let _ = use_after_free_intercepted(&input.value);
    "ok"
}

async fn cwe_416_safe(Query(input): Query<RustSpecificInput>) -> &'static str {
    let _ = lifetime_checked_use(&input.value);
    "ok"
}

async fn cwe_416_unknown(Query(input): Query<RustSpecificInput>) -> &'static str {
    ambiguous::memory_lifetime(&input.value);
    "ok"
}

async fn cwe_787_vulnerable(Query(input): Query<RustSpecificInput>) -> &'static str {
    let _ = out_of_bounds_write_intercepted(&input.value);
    "ok"
}

async fn cwe_787_safe(Query(input): Query<RustSpecificInput>) -> &'static str {
    let _ = bounds_checked_write(&input.value);
    "ok"
}

async fn cwe_787_unknown(Query(input): Query<RustSpecificInput>) -> &'static str {
    ambiguous::memory_write(&input.value);
    "ok"
}

async fn unsafe_vulnerable(Query(input): Query<RustSpecificInput>) -> &'static str {
    let _ = unsafe_precondition_intercepted(&input.value);
    "ok"
}

async fn unsafe_safe(Query(input): Query<RustSpecificInput>) -> &'static str {
    let _ = unsafe_precondition_checked(&input.value);
    "ok"
}

async fn unsafe_unknown(Query(input): Query<RustSpecificInput>) -> &'static str {
    ambiguous::unsafe_block(&input.value);
    "ok"
}

async fn ffi_vulnerable(Query(input): Query<RustSpecificInput>) -> &'static str {
    let _ = ffi_without_length_contract(&input.value);
    "ok"
}

async fn ffi_safe(Query(input): Query<RustSpecificInput>) -> &'static str {
    let _ = ffi_with_length_contract(&input.value);
    "ok"
}

async fn ffi_unknown(Query(input): Query<RustSpecificInput>) -> &'static str {
    ambiguous::ffi_boundary(&input.value);
    "ok"
}

async fn panic_vulnerable(Query(input): Query<RustSpecificInput>) -> &'static str {
    let _ = panic_from_request(&input.value);
    "ok"
}

async fn panic_safe(Query(input): Query<RustSpecificInput>) -> &'static str {
    let _ = panic_avoided(&input.value);
    "ok"
}

async fn panic_unknown(Query(input): Query<RustSpecificInput>) -> &'static str {
    ambiguous::panic_boundary(&input.value);
    "ok"
}

fn generic_memory_unchecked(value: &str) -> Result<String, Infallible> {
    Ok(violation("generic", value.len(), MEMORY_BOUND))
}

fn generic_memory_checked(value: &str) -> Result<String, Infallible> {
    let bounded = value.as_bytes().get(..value.len().min(MEMORY_BOUND));
    Ok(checked("generic", bounded.is_some(), MEMORY_BOUND))
}

fn out_of_bounds_read_intercepted(value: &str) -> Result<String, Infallible> {
    let bytes = [0_u8; MEMORY_BOUND];
    let index = value.len();
    if index >= bytes.len() {
        return Ok(violation("read", index, bytes.len()));
    }
    // SAFETY: the monitor above proves `index < bytes.len()` before the raw
    // access. The qualified vulnerable witness is the intercepted failing
    // precondition; Rig never performs undefined behavior to demonstrate it.
    let _ = unsafe { *bytes.as_ptr().add(index) };
    Ok(checked("read", true, bytes.len()))
}

fn bounds_checked_read(value: &str) -> Result<String, Infallible> {
    let bytes = [0_u8; MEMORY_BOUND];
    let _ = bytes.get(value.len());
    Ok(checked("read", true, bytes.len()))
}

fn use_after_free_intercepted(value: &str) -> Result<String, Infallible> {
    let allocation = Box::new(value.len());
    let pointer = Box::into_raw(allocation);
    // SAFETY: this exactly ends the allocation lifetime once. The monitor does
    // not dereference `pointer` afterwards; it reports the attempted use.
    unsafe { drop(Box::from_raw(pointer)) };
    Ok(violation("use_after_free", value.len(), 0))
}

fn lifetime_checked_use(value: &str) -> Result<String, Infallible> {
    let allocation = Box::new(value.len());
    let _ = *allocation;
    Ok(checked("lifetime", true, 1))
}

fn out_of_bounds_write_intercepted(value: &str) -> Result<String, Infallible> {
    let mut bytes = [0_u8; MEMORY_BOUND];
    let index = value.len();
    if index >= bytes.len() {
        return Ok(violation("write", index, bytes.len()));
    }
    // SAFETY: the preceding bounds check establishes the write precondition.
    unsafe { bytes.as_mut_ptr().add(index).write(1) };
    Ok(checked("write", true, bytes.len()))
}

fn bounds_checked_write(value: &str) -> Result<String, Infallible> {
    let mut bytes = [0_u8; MEMORY_BOUND];
    if let Some(cell) = bytes.get_mut(value.len()) {
        *cell = 1;
    }
    Ok(checked("write", true, bytes.len()))
}

fn unsafe_precondition_intercepted(value: &str) -> Result<String, Infallible> {
    Ok(violation("unsafe_block", value.len(), MEMORY_BOUND))
}

fn unsafe_precondition_checked(value: &str) -> Result<String, Infallible> {
    let _ = value.as_bytes().first();
    Ok(checked("unsafe_block", true, value.len()))
}

unsafe extern "C" {
    fn strlen(value: *const std::ffi::c_char) -> usize;
}

fn ffi_without_length_contract(value: &str) -> Result<String, Infallible> {
    let sanitized = value.replace('\0', "");
    let c_value = CString::new(sanitized).expect("NUL bytes removed");
    // SAFETY: `CString` supplies a valid NUL-terminated allocation. This call
    // intentionally lacks the application's required maximum-length contract.
    let observed = unsafe { strlen(c_value.as_ptr()) };
    Ok(format!("ffi_contract:violation:{observed}:{MEMORY_BOUND}"))
}

fn ffi_with_length_contract(value: &str) -> Result<String, Infallible> {
    if value.len() > MEMORY_BOUND {
        return Ok(format!("ffi_contract:checked:0:{MEMORY_BOUND}"));
    }
    let sanitized = value.replace('\0', "");
    let c_value = CString::new(sanitized).expect("NUL bytes removed");
    // SAFETY: `CString` supplies termination and the application validated the
    // declared maximum length before crossing the FFI boundary.
    let observed = unsafe { strlen(c_value.as_ptr()) };
    Ok(format!("ffi_contract:checked:{observed}:{MEMORY_BOUND}"))
}

fn panic_from_request(value: &str) -> usize {
    value
        .parse::<usize>()
        .expect("qualified panic boundary received non-numeric request input")
}

fn panic_avoided(value: &str) -> Option<usize> {
    value.parse::<usize>().ok()
}

fn violation(kind: &str, selected: usize, bound: usize) -> String {
    format!("memory_safety:violation:{kind}:{selected}:{bound}")
}

fn checked(kind: &str, complete: bool, bound: usize) -> String {
    format!("memory_safety:checked:{kind}:{complete}:{bound}")
}

mod ambiguous {
    pub fn memory_generic(_: &str) {}
    pub fn memory_read(_: &str) {}
    pub fn memory_lifetime(_: &str) {}
    pub fn memory_write(_: &str) {}
    pub fn unsafe_block(_: &str) {}
    pub fn ffi_boundary(_: &str) {}
    pub fn panic_boundary(_: &str) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_monitor_reports_preconditions_without_executing_undefined_behavior() {
        let marker = "IASTr00000001x1234567890abcdef";
        assert!(out_of_bounds_read_intercepted(marker)
            .unwrap()
            .starts_with("memory_safety:violation:read:"));
        assert!(use_after_free_intercepted(marker)
            .unwrap()
            .starts_with("memory_safety:violation:use_after_free:"));
        assert!(out_of_bounds_write_intercepted(marker)
            .unwrap()
            .starts_with("memory_safety:violation:write:"));
    }

    #[test]
    fn ffi_monitor_distinguishes_missing_and_enforced_contracts() {
        let marker = "IASTr00000001x1234567890abcdef";
        assert!(ffi_without_length_contract(marker)
            .unwrap()
            .starts_with("ffi_contract:violation:"));
        assert_eq!(
            ffi_with_length_contract(marker).unwrap(),
            format!("ffi_contract:checked:0:{MEMORY_BOUND}")
        );
    }
}
