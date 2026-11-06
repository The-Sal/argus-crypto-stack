//! C ABI matching `Argus/argus/perpetuals/lighter/_signer.py`'s ctypes contract.
//!
//! Every `sign_*` returns a [`SignedTxResponse`] whose strings are heap-allocated
//! C strings freed via [`Free`]. All entry points swallow panics into the `err`
//! field, exactly like the Go shared library.

use std::ffi::{c_char, c_void, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr::null_mut;
use std::time::{SystemTime, UNIX_EPOCH};

use lighters::attributes::TxAttributes;
use lighters::client::{OrderReq, TransactOpts};
use lighters::error::Result as LighterResult;
use lighters::http::HttpClient;
use lighters::transactions::{to_signed, SignedTransaction};
use lighters::TxClient;

use crate::lighter::client as registry;
use crate::lighter::http::UreqClient;

const NIL_MARKET_INDEX: i32 = 255;
const NIL_ORDER_EXPIRY: i64 = -1;

// --- ctypes-compatible structures -------------------------------------------

#[repr(C)]
pub struct ApiKeyResponse {
    pub private_key: *mut c_char,
    pub public_key: *mut c_char,
    pub err: *mut c_char,
}

#[repr(C)]
pub struct StrOrErr {
    pub string: *mut c_char,
    pub err: *mut c_char,
}

#[repr(C)]
pub struct SignedTxResponse {
    pub tx_type: u8,
    pub tx_info: *mut c_char,
    pub tx_hash: *mut c_char,
    pub message_to_sign: *mut c_char,
    pub err: *mut c_char,
}

// --- helpers ----------------------------------------------------------------

/// Allocates a NUL-terminated C string (NUL bytes in `s` are stripped).
fn cstring(s: impl Into<String>) -> *mut c_char {
    let s = s.into();
    let mut bytes = Vec::with_capacity(s.len() + 1);
    bytes.extend_from_slice(s.as_bytes());
    bytes.retain(|&b| b != 0);
    bytes.push(0);
    // Safe: we pushed a trailing 0 and removed interior 0s.
    unsafe { CString::from_vec_with_nul_unchecked(bytes) }.into_raw()
}

fn err_response(msg: impl Into<String>) -> SignedTxResponse {
    SignedTxResponse {
        tx_type: 0,
        tx_info: null_mut(),
        tx_hash: null_mut(),
        message_to_sign: null_mut(),
        err: cstring(msg),
    }
}

fn ok_response(s: SignedTransaction) -> SignedTxResponse {
    SignedTxResponse {
        tx_type: s.tx_type,
        tx_info: cstring(s.tx_info),
        tx_hash: cstring(s.tx_hash),
        message_to_sign: s.message_to_sign.map(cstring).unwrap_or(null_mut()),
        err: null_mut(),
    }
}

fn guard<T>(fallback: impl FnOnce() -> T, f: impl FnOnce() -> T) -> T {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(v) => v,
        Err(_) => fallback(),
    }
}

fn now_unix_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn now_unix_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn read_cstr(ptr: *const c_char) -> String {
    if ptr.is_null() {
        return String::new();
    }
    unsafe { std::ffi::CStr::from_ptr(ptr) }
        .to_string_lossy()
        .into_owned()
}

/// Common finishing step: sign produced a tx, serialise it to a response.
fn finish<T: lighters::transactions::TxInfo>(
    client: &TxClient,
    result: LighterResult<T>,
) -> SignedTxResponse {
    match result.and_then(|tx| to_signed(&tx, client.chain_id())) {
        Ok(signed) => ok_response(signed),
        Err(e) => err_response(e.to_string()),
    }
}

fn sign_opts(nonce: i64, attrs: TxAttributes) -> TransactOpts {
    TransactOpts {
        from_account_index: None,
        api_key_index: None,
        expired_at: None,
        // Go refetches the nonce over HTTP when it is -1.
        nonce: if nonce == -1 { None } else { Some(nonce) },
        tx_attributes: Some(attrs),
    }
}

// --- exports ----------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn GenerateAPIKey() -> ApiKeyResponse {
    guard(
        || ApiKeyResponse {
            private_key: null_mut(),
            public_key: null_mut(),
            err: cstring("internal error generating API key"),
        },
        || {
            let (private_key, public_key) = lighters::generate_api_key();
            ApiKeyResponse {
                private_key: cstring(private_key),
                public_key: cstring(public_key),
                err: null_mut(),
            }
        },
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn CreateClient(
    url: *const c_char,
    private_key: *const c_char,
    chain_id: i32,
    api_key_index: i32,
    account_index: i64,
) -> *mut c_char {
    guard(
        || cstring("internal error creating client"),
        || {
            let url = read_cstr(url);
            let private_key = read_cstr(private_key);
            match registry::create_client(
                &url,
                &private_key,
                chain_id as u32,
                api_key_index as u8,
                account_index,
            ) {
                Ok(()) => null_mut(),
                Err(e) => cstring(e),
            }
        },
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn CheckClient(api_key_index: i32, account_index: i64) -> *mut c_char {
    guard(
        || cstring("internal error checking client"),
        || {
            let entry = match registry::get_client(api_key_index as u8, account_index) {
                Ok(e) => e,
                Err(e) => return cstring(e),
            };
            // Go's `TxClient.Check` uses the client's own bound indices.
            let account = entry.client.account_index();
            let key_index = entry.client.api_key_index();
            let expected = entry.client.key_manager().public_key_hex();
            let expected = expected.strip_prefix("0x").unwrap_or(&expected).to_string();

            let http = UreqClient::new(&entry.endpoint);
            match http.get_api_key(account, key_index) {
                Ok(public_key) if public_key == expected => null_mut(),
                Ok(public_key) => cstring(format!(
                    "private key does not match the one on Lighter. ownPubKey: {expected} response: {public_key}"
                )),
                Err(e) => cstring(e.to_string()),
            }
        },
    )
}

/// All inputs of a create-order signature (the `SignCreateOrder` argument list as a struct), so
/// the one-shot `LighterCreateOrder` signs through exactly the same code path.
pub(crate) struct CreateOrderArgs {
    pub market_index: i32,
    pub client_order_index: i64,
    pub base_amount: i64,
    pub price: i32,
    pub is_ask: i32,
    pub order_type: i32,
    pub time_in_force: i32,
    pub reduce_only: i32,
    pub trigger_price: i32,
    pub order_expiry: i64,
    pub integrator_account_index: i64,
    pub integrator_taker_fee: i32,
    pub integrator_maker_fee: i32,
    pub self_trade_behavior_mode: u8,
    pub self_trade_equality_mode: u8,
    pub skip_nonce: u8,
    pub nonce: i64,
}

/// Builds and signs a create-order tx with `entry`'s client.
pub(crate) fn sign_create_order_core(
    entry: &registry::Entry,
    a: &CreateOrderArgs,
) -> Result<SignedTransaction, String> {
    // Go maps a -1 expiry to "now + 28 days" before hashing/signing.
    let order_expiry = if a.order_expiry == NIL_ORDER_EXPIRY {
        now_unix_millis() + 28 * 24 * 60 * 60 * 1000
    } else {
        a.order_expiry
    };

    let attrs = TxAttributes {
        integrator_account_index: (a.integrator_account_index != 0)
            .then_some(a.integrator_account_index),
        integrator_taker_fee: (a.integrator_taker_fee != 0).then_some(a.integrator_taker_fee as u32),
        integrator_maker_fee: (a.integrator_maker_fee != 0).then_some(a.integrator_maker_fee as u32),
        skip_nonce: (a.skip_nonce == 1).then_some(1),
        cancel_all_market_index: None,
        self_trade_behavior_mode: (a.self_trade_behavior_mode != 0)
            .then_some(a.self_trade_behavior_mode),
        self_trade_equality_mode: (a.self_trade_equality_mode != 0)
            .then_some(a.self_trade_equality_mode),
    };

    let order = OrderReq {
        market_index: a.market_index as i16,
        client_order_index: a.client_order_index,
        base_amount: a.base_amount,
        price: a.price as u32,
        is_ask: a.is_ask as u8,
        order_type: a.order_type as u8,
        time_in_force: a.time_in_force as u8,
        reduce_only: a.reduce_only as u8,
        trigger_price: a.trigger_price as u32,
        order_expiry,
    };

    let opts = sign_opts(a.nonce, attrs);
    entry
        .client
        .create_order(order, &opts)
        .and_then(|tx| to_signed(&tx, entry.client.chain_id()))
        .map_err(|e| e.to_string())
}

#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub extern "C" fn SignCreateOrder(
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
) -> SignedTxResponse {
    guard(
        || err_response("internal error signing create order"),
        || {
            let entry = match registry::get_client(api_key_index as u8, account_index) {
                Ok(e) => e,
                Err(e) => return err_response(e),
            };
            let args = CreateOrderArgs {
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
            };
            match sign_create_order_core(&entry, &args) {
                Ok(signed) => ok_response(signed),
                Err(e) => err_response(e),
            }
        },
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn SignCancelOrder(
    market_index: i32,
    order_index: i64,
    skip_nonce: u8,
    nonce: i64,
    api_key_index: i32,
    account_index: i64,
) -> SignedTxResponse {
    guard(
        || err_response("internal error signing cancel order"),
        || {
            let entry = match registry::get_client(api_key_index as u8, account_index) {
                Ok(e) => e,
                Err(e) => return err_response(e),
            };
            let attrs = TxAttributes {
                skip_nonce: (skip_nonce == 1).then_some(1),
                ..Default::default()
            };
            let opts = sign_opts(nonce, attrs);
            finish(
                &entry.client,
                entry.client.cancel_order(market_index as i16, order_index, &opts),
            )
        },
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn SignCancelAllOrders(
    time_in_force: i32,
    timestamp_ms: i64,
    cancel_all_market_index: i32,
    skip_nonce: u8,
    nonce: i64,
    api_key_index: i32,
    account_index: i64,
) -> SignedTxResponse {
    guard(
        || err_response("internal error signing cancel all orders"),
        || {
            let entry = match registry::get_client(api_key_index as u8, account_index) {
                Ok(e) => e,
                Err(e) => return err_response(e),
            };
            let attrs = TxAttributes {
                cancel_all_market_index: (cancel_all_market_index != NIL_MARKET_INDEX)
                    .then_some(cancel_all_market_index as i16),
                skip_nonce: (skip_nonce == 1).then_some(1),
                ..Default::default()
            };
            let opts = sign_opts(nonce, attrs);
            finish(
                &entry.client,
                entry.client.cancel_all_orders(time_in_force as u8, timestamp_ms, &opts),
            )
        },
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn SignUpdateLeverage(
    market_index: i32,
    initial_margin_fraction: i32,
    margin_mode: i32,
    skip_nonce: u8,
    nonce: i64,
    api_key_index: i32,
    account_index: i64,
) -> SignedTxResponse {
    guard(
        || err_response("internal error signing update leverage"),
        || {
            let entry = match registry::get_client(api_key_index as u8, account_index) {
                Ok(e) => e,
                Err(e) => return err_response(e),
            };
            let attrs = TxAttributes {
                skip_nonce: (skip_nonce == 1).then_some(1),
                ..Default::default()
            };
            let opts = sign_opts(nonce, attrs);
            finish(
                &entry.client,
                entry.client.update_leverage(
                    market_index as i16,
                    initial_margin_fraction as u16,
                    margin_mode as u8,
                    &opts,
                ),
            )
        },
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn CreateAuthToken(
    deadline: i64,
    api_key_index: i32,
    account_index: i64,
) -> StrOrErr {
    guard(
        || StrOrErr {
            string: null_mut(),
            err: cstring("internal error creating auth token"),
        },
        || {
            let entry = match registry::get_client(api_key_index as u8, account_index) {
                Ok(e) => e,
                Err(e) => return StrOrErr { string: null_mut(), err: cstring(e) },
            };
            // Go defaults a 0 deadline to now + 7 hours.
            let deadline = if deadline == 0 {
                now_unix_secs() + 7 * 3600
            } else {
                deadline
            };
            match entry.client.auth_token(deadline, &TransactOpts::default()) {
                Ok(token) => StrOrErr { string: cstring(token), err: null_mut() },
                Err(e) => StrOrErr { string: null_mut(), err: cstring(e.to_string()) },
            }
        },
    )
}

/// Frees any C string returned by this library. Must be used on every pointer
/// the `*Response` structs hand out.
#[unsafe(no_mangle)]
pub extern "C" fn Free(ptr: *mut c_void) {
    if ptr.is_null() {
        return;
    }
    // Reclaim the Rust-allocated CString.
    unsafe { drop(CString::from_raw(ptr as *mut c_char)) };
}
