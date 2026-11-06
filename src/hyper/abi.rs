//! C ABI for Hyperliquid L1 (phantom-agent) signing.
//!
//! Argus packs the action dict with msgpack (serialization, not crypto) and
//! hands the bytes here; ACS computes the action hash and EIP-712 signature
//! natively (no personal-message prefix).

use std::ffi::{c_char, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;

use crate::hyper::eip712::{eip712_hash, keccak256};
use crate::hyper::secp;

/// Recoverable signature + error pointer. `err` is a heap C string freed with
/// [`crate::lighter::abi::Free`] (same allocator).
#[repr(C)]
pub struct HlSig {
    pub r: [u8; 32],
    pub s: [u8; 32],
    /// 27 or 28.
    pub v: u8,
    pub err: *mut c_char,
}

fn cstring(s: impl Into<String>) -> *mut c_char {
    let s = s.into();
    let mut bytes = Vec::with_capacity(s.len() + 1);
    bytes.extend_from_slice(s.as_bytes());
    bytes.retain(|&b| b != 0);
    bytes.push(0);
    unsafe { CString::from_vec_with_nul_unchecked(bytes) }.into_raw()
}

fn err_sig(msg: impl Into<String>) -> HlSig {
    HlSig {
        r: [0u8; 32],
        s: [0u8; 32],
        v: 0,
        err: cstring(msg),
    }
}

fn read_cstr(ptr: *const c_char) -> String {
    if ptr.is_null() {
        return String::new();
    }
    unsafe { std::ffi::CStr::from_ptr(ptr) }
        .to_string_lossy()
        .into_owned()
}

/// Parses an optional vault address; `None` when absent/empty.
fn parse_vault(ptr: *const c_char) -> Result<Option<[u8; 20]>, String> {
    let s = read_cstr(ptr);
    let s = s.trim();
    if s.is_empty() {
        return Ok(None);
    }
    let hex_part = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(hex_part).map_err(|e| format!("invalid vault address hex: {e}"))?;
    if bytes.len() != 20 {
        return Err(format!(
            "invalid vault address length: expected 20 bytes, got {}",
            bytes.len()
        ));
    }
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&bytes);
    Ok(Some(addr))
}

/// `msgpack(action) || nonce(8B BE) || vault-tag || [0x00 || expiresAfter(8B BE)]`.
pub(crate) fn action_preimage(
    action: &[u8],
    nonce: i64,
    vault: Option<&[u8; 20]>,
    expires_after: Option<i64>,
) -> Vec<u8> {
    let mut data = Vec::with_capacity(action.len() + 1 + 20 + 9);
    data.extend_from_slice(action);
    data.extend_from_slice(&nonce.to_be_bytes());
    match vault {
        None => data.push(0x00),
        Some(addr) => {
            data.push(0x01);
            data.extend_from_slice(addr);
        }
    }
    if let Some(expires) = expires_after {
        data.push(0x00);
        data.extend_from_slice(&expires.to_be_bytes());
    }
    data
}

unsafe fn action_slice<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    if len == 0 || ptr.is_null() {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(ptr, len) }
    }
}

/// Writes the 32-byte keccak action hash to `out_hash`.
///
/// Returns `0` on success, non-zero on error.
///
/// # Safety
/// `action_packed` must point to `action_len` readable bytes (or be null when
/// `action_len == 0`); `out_hash` must point to 32 writable bytes;
/// `vault_address` must be null or a valid NUL-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn HlActionHash(
    action_packed: *const u8,
    action_len: usize,
    nonce: i64,
    vault_address: *const c_char,
    expires_after: i64,
    has_expires_after: u8,
    out_hash: *mut u8,
) -> i32 {
    if out_hash.is_null() {
        return -1;
    }
    match catch_unwind(AssertUnwindSafe(|| {
        let action = unsafe { action_slice(action_packed, action_len) };
        let vault = parse_vault(vault_address)?;
        let expires = (has_expires_after != 0).then_some(expires_after);
        Ok::<[u8; 32], String>(keccak256(&action_preimage(
            action,
            nonce,
            vault.as_ref(),
            expires,
        )))
    })) {
        Ok(Ok(hash)) => {
            unsafe { ptr::copy_nonoverlapping(hash.as_ptr(), out_hash, 32) };
            0
        }
        _ => -1,
    }
}

/// Signs a Hyperliquid action, returning `{ r, s, v }` or an error string.
///
/// `vault_address` may be NULL/empty. `has_expires_after` selects the trailing
/// expires block. `is_mainnet` selects the EIP-712 `source` tag ("a"/"b").
///
/// # Safety
/// `private_key_hex` and `vault_address` must be null or valid NUL-terminated
/// strings; `action_packed` must point to `action_len` readable bytes (or be
/// null when `action_len == 0`).
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn HlSignAction(
    private_key_hex: *const c_char,
    action_packed: *const u8,
    action_len: usize,
    nonce: i64,
    vault_address: *const c_char,
    expires_after: i64,
    has_expires_after: u8,
    is_mainnet: i32,
) -> HlSig {
    match catch_unwind(AssertUnwindSafe(|| {
        let key_hex = read_cstr(private_key_hex);
        let secret = secp::parse_private_key(&key_hex)?;
        let action = unsafe { action_slice(action_packed, action_len) };
        let vault = parse_vault(vault_address)?;
        let expires = (has_expires_after != 0).then_some(expires_after);

        let connection_id = keccak256(&action_preimage(action, nonce, vault.as_ref(), expires));
        let source = if is_mainnet != 0 { "a" } else { "b" };
        let digest = eip712_hash(source, &connection_id);
        secp::sign_eip712_digest(&secret, &digest)
    })) {
        Ok(Ok(sig)) => HlSig {
            r: sig.r,
            s: sig.s,
            v: sig.v,
            err: ptr::null_mut(),
        },
        Ok(Err(e)) => err_sig(e),
        Err(_) => err_sig("internal error signing hyperliquid action"),
    }
}
