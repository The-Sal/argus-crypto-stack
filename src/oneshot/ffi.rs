//! Shared C-ABI plumbing for the one-shot (sign + POST) exports.
//!
//! Every one-shot export returns a [`OneShotResponse`]. Its strings are heap C strings freed with
//! the library's existing `Free`; a null pointer means "absent". The `kind` field tells the caller
//! what happened to the request, which is exactly what a nonce-managing caller needs to know:
//!
//! | kind | meaning | nonce guidance |
//! |---|---|---|
//! | [`KIND_OK`] (0) | an HTTP response was received; inspect `http_status` / `body` | consumed (the venue may still have rejected it: that is the caller's call) |
//! | [`KIND_NOT_SENT`] (1) | rejected locally (bad input, unknown client, signing failure); nothing left the process | safe to release |
//! | [`KIND_UNKNOWN`] (2) | transport failure mid-flight (connect/TLS/timeout/read); the venue may or may not have the request | treat as uncertain: re-read the venue nonce |

use std::ffi::{c_char, CStr, CString};
use std::ptr::null_mut;

pub const KIND_OK: i32 = 0;
pub const KIND_NOT_SENT: i32 = 1;
pub const KIND_UNKNOWN: i32 = 2;

#[repr(C)]
pub struct OneShotResponse {
    pub kind: i32,
    pub http_status: i32,
    /// Response body (valid when `kind == 0`).
    pub body: *mut c_char,
    /// Value of the `Retry-After` response header, if any.
    pub retry_after: *mut c_char,
    /// Lighter: the signer's tx hash. Null for Hyperliquid.
    pub tx_hash: *mut c_char,
    /// Lighter: the exact `tx_info` JSON that was POSTed. Null for Hyperliquid.
    pub tx_info: *mut c_char,
    /// Error text when `kind != 0`.
    pub err: *mut c_char,
}

/// What a one-shot call did; converted to the C struct at the boundary.
#[derive(Debug)]
pub enum Outcome {
    Sent {
        status: u16,
        body: Vec<u8>,
        retry_after: Option<String>,
        tx_hash: Option<String>,
        tx_info: Option<String>,
    },
    NotSent(String),
    Unknown(String),
}

/// Allocates a NUL-terminated C string (NUL bytes in `s` are stripped).
pub(crate) fn cstring(s: impl AsRef<[u8]>) -> *mut c_char {
    let mut bytes: Vec<u8> = s.as_ref().iter().copied().filter(|&b| b != 0).collect();
    bytes.push(0);
    // Safe: interior NULs were removed and a trailing NUL was appended.
    unsafe { CString::from_vec_with_nul_unchecked(bytes) }.into_raw()
}

fn opt_cstring(s: Option<String>) -> *mut c_char {
    s.map(cstring).unwrap_or(null_mut())
}

/// `None` for a null pointer, otherwise the (lossy UTF-8) string.
pub(crate) fn read_opt(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() {
        None
    } else {
        Some(unsafe { CStr::from_ptr(ptr) }.to_string_lossy().into_owned())
    }
}

impl Outcome {
    pub fn into_ffi(self) -> OneShotResponse {
        match self {
            Outcome::Sent { status, body, retry_after, tx_hash, tx_info } => OneShotResponse {
                kind: KIND_OK,
                http_status: status as i32,
                body: cstring(body),
                retry_after: opt_cstring(retry_after),
                tx_hash: opt_cstring(tx_hash),
                tx_info: opt_cstring(tx_info),
                err: null_mut(),
            },
            Outcome::NotSent(e) => Self::failed(KIND_NOT_SENT, e),
            Outcome::Unknown(e) => Self::failed(KIND_UNKNOWN, e),
        }
    }

    fn failed(kind: i32, err: String) -> OneShotResponse {
        OneShotResponse {
            kind,
            http_status: 0,
            body: null_mut(),
            retry_after: null_mut(),
            tx_hash: null_mut(),
            tx_info: null_mut(),
            err: cstring(err),
        }
    }
}

/// Runs `f`, turning a panic into a `NotSent` outcome (nothing is known to have been sent).
pub(crate) fn guard(f: impl FnOnce() -> Outcome) -> OneShotResponse {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(outcome) => outcome.into_ffi(),
        Err(_) => Outcome::NotSent("internal error in one-shot call".into()).into_ffi(),
    }
}
