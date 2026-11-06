//! Lighter one-shot: order primitives -> sign -> form-encode -> POST `/api/v1/sendTx` -> response.
//!
//! Signing goes through the same core as `SignCreateOrder` (so the tx is identical); the signing
//! client and endpoint come from the registry populated by `CreateClient`. The caller owns nonce
//! allocation: `nonce` is required and `-1` ("fetch it for me") is rejected, because a hidden nonce
//! fetch would bypass the caller's local counter and its cross-thread ordering.

use std::collections::HashMap;
use std::ffi::c_char;
use std::sync::{Arc, Mutex, OnceLock};

use crate::lighter::abi::{sign_create_order_core, CreateOrderArgs};
use crate::lighter::client as registry;
use crate::oneshot::ffi::{cstring, guard, read_opt, Outcome};
use crate::oneshot::net::Transport;
use crate::oneshot::ffi::OneShotResponse;

static TRANSPORTS: OnceLock<Mutex<HashMap<(u8, i64), Arc<Transport>>>> = OnceLock::new();

fn transports() -> &'static Mutex<HashMap<(u8, i64), Arc<Transport>>> {
    TRANSPORTS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// The pooled transport for a client, created with defaults (no proxy) on first use.
fn transport_for(api_key_index: u8, account_index: i64) -> Result<Arc<Transport>, String> {
    let mut map = transports().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(t) = map.get(&(api_key_index, account_index)) {
        return Ok(t.clone());
    }
    let t = Transport::shared(None, None, 0, 0)?;
    map.insert((api_key_index, account_index), t.clone());
    Ok(t)
}

/// Percent-encode like Python's `urllib.parse.quote_plus` (what `requests` uses for `data=`):
/// unreserved = ASCII alphanumerics and `_.-~`; space becomes `+`; everything else `%XX`.
/// This matters: the base64 signature inside `tx_info` contains `+`, `/` and `=`.
pub fn form_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + s.len() / 4);
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-' | b'~' => out.push(b as char),
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Sign and POST one create-order tx using `net`. See [`LighterCreateOrder`].
pub(crate) fn create_order(
    api_key_index: i32,
    account_index: i64,
    args: &CreateOrderArgs,
) -> Outcome {
    if args.nonce < 0 {
        return Outcome::NotSent(
            "a non-negative nonce is required (one-shot calls never fetch nonces)".into(),
        );
    }
    let entry = match registry::get_client(api_key_index as u8, account_index) {
        Ok(e) => e,
        Err(e) => return Outcome::NotSent(e),
    };
    let net = match transport_for(api_key_index as u8, account_index) {
        Ok(n) => n,
        Err(e) => return Outcome::NotSent(e),
    };
    let signed = match sign_create_order_core(&entry, args) {
        Ok(s) => s,
        Err(e) => return Outcome::NotSent(e),
    };
    let body = format!("tx_type={}&tx_info={}", signed.tx_type, form_encode(&signed.tx_info));
    let url = format!("{}/api/v1/sendTx", entry.endpoint);
    match net.post(&url, "application/x-www-form-urlencoded", body.as_bytes()) {
        Ok(r) => Outcome::Sent {
            status: r.status,
            body: r.body,
            retry_after: r.retry_after,
            tx_hash: Some(signed.tx_hash),
            tx_info: Some(signed.tx_info),
        },
        Err(e) => Outcome::Unknown(e),
    }
}

/// Configures the pooled transport used by the one-shot calls of a client registered with
/// `CreateClient`. Optional: without it a direct (no proxy) transport with default timeouts is
/// used. Replaces any previous transport, dropping its pooled connections. Returns NULL on
/// success or an error string (free with `Free`).
///
/// # Safety
/// String arguments must be NULL or valid NUL-terminated strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn LighterSetTransport(
    api_key_index: i32,
    account_index: i64,
    proxy_url: *const c_char,
    ca_pem_path: *const c_char,
    timeout_ms: i64,
    idle_ms: i64,
) -> *mut c_char {
    let r = std::panic::catch_unwind(|| -> Result<(), String> {
        let t = Transport::shared(
            read_opt(proxy_url).as_deref(),
            read_opt(ca_pem_path).as_deref(),
            timeout_ms.max(0) as u64,
            idle_ms.max(0) as u64,
        )?;
        transports().lock().unwrap_or_else(|e| e.into_inner()).insert((api_key_index as u8, account_index), t);
        Ok(())
    });
    match r {
        Ok(Ok(())) => std::ptr::null_mut(),
        Ok(Err(e)) => cstring(e),
        Err(_) => cstring("internal error configuring transport"),
    }
}

/// Sign a create-order tx (same arguments as `SignCreateOrder`) and POST it to `/api/v1/sendTx` in
/// one call. `nonce` must be >= 0. On `kind == 0` the response carries the HTTP status and body,
/// plus the signer's `tx_hash` and the exact `tx_info` that was sent.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub extern "C" fn LighterCreateOrder(
    market_index: i32,
    client_order_index: i64,
    base_amount: i64,
    price: i32,
    is_ask: i32,
    order_type: i32,
    time_in_force: i32,
    reduce_only: i32,
    trigger_price: i32,
    order_expiry: i64,
    integrator_account_index: i64,
    integrator_taker_fee: i32,
    integrator_maker_fee: i32,
    self_trade_behavior_mode: u8,
    self_trade_equality_mode: u8,
    skip_nonce: u8,
    nonce: i64,
    api_key_index: i32,
    account_index: i64,
) -> OneShotResponse {
    guard(|| {
        create_order(
            api_key_index,
            account_index,
            &CreateOrderArgs {
                market_index,
                client_order_index,
                base_amount,
                price,
                is_ask,
                order_type,
                time_in_force,
                reduce_only,
                trigger_price,
                order_expiry,
                integrator_account_index,
                integrator_taker_fee,
                integrator_maker_fee,
                self_trade_behavior_mode,
                self_trade_equality_mode,
                skip_nonce,
                nonce,
            },
        )
    })
}
