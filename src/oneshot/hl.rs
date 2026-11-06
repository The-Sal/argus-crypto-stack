//! Hyperliquid one-shot: order primitives -> msgpack -> keccak -> EIP-712 sign -> JSON -> POST
//! `/exchange` -> response body, in a single call.
//!
//! The wire format mirrors `argus/perpetuals/hyper/exchange.py` (`_build_wire_order`,
//! `sign_action`, `_post_action`) exactly: msgpack key order is part of the signature
//! (`a b p s r t [c]`, action `type orders grouping`), `use_bin_type` string encodings, and the
//! request body `{action, nonce, signature, vaultAddress, expiresAfter}`.
//!
//! Price/size rounding, asset-id resolution and nonce allocation stay with the caller: the caller
//! owns the nonce and passes it in.

use std::ffi::{c_char, c_void};
use std::sync::Arc;

use crate::hyper::abi::action_preimage;
use crate::hyper::eip712::{eip712_hash, keccak256};
use crate::hyper::secp;
use crate::oneshot::ffi::{cstring, guard, read_opt, Outcome, OneShotResponse};
use crate::oneshot::net::Transport;

const VALID_TIFS: [&str; 3] = ["Gtc", "Ioc", "Alo"];

/// One limit order, in venue-wire terms (already rounded/validated by the caller).
#[derive(Debug, Clone, Copy)]
pub struct OrderPrim<'a> {
    pub asset: u32,
    pub is_buy: bool,
    pub reduce_only: bool,
    /// Wire number string, e.g. `"50000.5"`.
    pub price: &'a str,
    pub size: &'a str,
    /// `Gtc`, `Ioc` or `Alo`.
    pub tif: &'a str,
    pub cloid: Option<&'a str>,
}

pub struct HlClient {
    secret: Vec<u8>,
    source: &'static str,
    vault: Option<[u8; 20]>,
    vault_str: Option<String>,
    url: String,
    net: Arc<Transport>,
}

// --- msgpack (what `msgpack.packb(x, use_bin_type=True)` emits for these shapes) -------------

fn mp_map(o: &mut Vec<u8>, n: usize) {
    debug_assert!(n < 16);
    o.push(0x80 | n as u8);
}

fn mp_array(o: &mut Vec<u8>, n: usize) {
    if n < 16 {
        o.push(0x90 | n as u8);
    } else if n < 65_536 {
        o.push(0xdc);
        o.extend_from_slice(&(n as u16).to_be_bytes());
    } else {
        o.push(0xdd);
        o.extend_from_slice(&(n as u32).to_be_bytes());
    }
}

fn mp_str(o: &mut Vec<u8>, s: &str) {
    let n = s.len();
    if n < 32 {
        o.push(0xa0 | n as u8);
    } else if n < 256 {
        o.extend_from_slice(&[0xd9, n as u8]);
    } else if n < 65_536 {
        o.push(0xda);
        o.extend_from_slice(&(n as u16).to_be_bytes());
    } else {
        o.push(0xdb);
        o.extend_from_slice(&(n as u32).to_be_bytes());
    }
    o.extend_from_slice(s.as_bytes());
}

fn mp_uint(o: &mut Vec<u8>, v: u32) {
    if v < 128 {
        o.push(v as u8);
    } else if v < 256 {
        o.extend_from_slice(&[0xcc, v as u8]);
    } else if v < 65_536 {
        o.push(0xcd);
        o.extend_from_slice(&(v as u16).to_be_bytes());
    } else {
        o.push(0xce);
        o.extend_from_slice(&v.to_be_bytes());
    }
}

fn mp_bool(o: &mut Vec<u8>, b: bool) {
    o.push(if b { 0xc3 } else { 0xc2 });
}

fn validate(orders: &[OrderPrim]) -> Result<(), String> {
    if orders.is_empty() {
        return Err("at least one order is required".into());
    }
    for o in orders {
        if !VALID_TIFS.contains(&o.tif) {
            return Err(format!("invalid tif {:?}: expected one of {VALID_TIFS:?}", o.tif));
        }
    }
    Ok(())
}

/// `msgpack({"type":"order","orders":[...],"grouping":"na"})`, byte-identical to the Python packer.
pub fn encode_orders_msgpack(orders: &[OrderPrim]) -> Result<Vec<u8>, String> {
    validate(orders)?;
    let mut m = Vec::with_capacity(64 + orders.len() * 72);
    mp_map(&mut m, 3);
    mp_str(&mut m, "type");
    mp_str(&mut m, "order");
    mp_str(&mut m, "orders");
    mp_array(&mut m, orders.len());
    for o in orders {
        mp_map(&mut m, if o.cloid.is_some() { 7 } else { 6 });
        mp_str(&mut m, "a");
        mp_uint(&mut m, o.asset);
        mp_str(&mut m, "b");
        mp_bool(&mut m, o.is_buy);
        mp_str(&mut m, "p");
        mp_str(&mut m, o.price);
        mp_str(&mut m, "s");
        mp_str(&mut m, o.size);
        mp_str(&mut m, "r");
        mp_bool(&mut m, o.reduce_only);
        mp_str(&mut m, "t");
        mp_map(&mut m, 1);
        mp_str(&mut m, "limit");
        mp_map(&mut m, 1);
        mp_str(&mut m, "tif");
        mp_str(&mut m, o.tif);
        if let Some(c) = o.cloid {
            mp_str(&mut m, "c");
            mp_str(&mut m, c);
        }
    }
    mp_str(&mut m, "grouping");
    mp_str(&mut m, "na");
    Ok(m)
}

fn json_str(s: &str) -> String {
    // serde_json escapes quotes, backslashes and control characters.
    serde_json::to_string(s).expect("string serialises")
}

fn parse_vault(v: &str) -> Result<[u8; 20], String> {
    let hex_part = v.strip_prefix("0x").unwrap_or(v);
    let bytes = hex::decode(hex_part).map_err(|e| format!("invalid vault address hex: {e}"))?;
    <[u8; 20]>::try_from(bytes.as_slice())
        .map_err(|_| format!("invalid vault address length: expected 20 bytes, got {}", bytes.len()))
}

impl HlClient {
    pub fn new(
        base_url: &str,
        private_key_hex: &str,
        is_mainnet: bool,
        vault_address: Option<&str>,
        net: Arc<Transport>,
    ) -> Result<Self, String> {
        let vault_str = vault_address.filter(|v| !v.is_empty()).map(str::to_owned);
        let vault = vault_str.as_deref().map(parse_vault).transpose()?;
        Ok(Self {
            secret: secp::parse_private_key(private_key_hex)?,
            source: if is_mainnet { "a" } else { "b" },
            vault,
            vault_str,
            url: format!("{}/exchange", base_url.trim_end_matches('/')),
            net,
        })
    }

    /// The exact JSON request body for `orders` (also what `place_orders` POSTs).
    pub fn build_body(
        &self,
        orders: &[OrderPrim],
        nonce: i64,
        expires_after: Option<i64>,
    ) -> Result<String, String> {
        if nonce < 0 {
            return Err(format!("invalid nonce {nonce}"));
        }
        let packed = encode_orders_msgpack(orders)?;
        let digest = eip712_hash(
            self.source,
            &keccak256(&action_preimage(&packed, nonce, self.vault.as_ref(), expires_after)),
        );
        let sig = secp::sign_eip712_digest(&self.secret, &digest)?;

        let mut j = String::with_capacity(256 + orders.len() * 128);
        j.push_str(r#"{"action":{"type":"order","orders":["#);
        for (i, o) in orders.iter().enumerate() {
            if i > 0 {
                j.push(',');
            }
            j.push_str(&format!(
                r#"{{"a":{},"b":{},"p":{},"s":{},"r":{},"t":{{"limit":{{"tif":{}}}}}"#,
                o.asset,
                o.is_buy,
                json_str(o.price),
                json_str(o.size),
                o.reduce_only,
                json_str(o.tif),
            ));
            if let Some(c) = o.cloid {
                j.push_str(&format!(r#","c":{}"#, json_str(c)));
            }
            j.push('}');
        }
        j.push_str(&format!(
            r#"],"grouping":"na"}},"nonce":{nonce},"signature":{{"r":"0x{}","s":"0x{}","v":{}}},"vaultAddress":{},"expiresAfter":{}}}"#,
            hex::encode(sig.r),
            hex::encode(sig.s),
            sig.v,
            self.vault_str.as_deref().map(json_str).unwrap_or_else(|| "null".into()),
            expires_after.map(|e| e.to_string()).unwrap_or_else(|| "null".into()),
        ));
        Ok(j)
    }

    /// Sign and POST a batch of limit orders (a single order is a batch of one).
    pub fn place_orders(&self, orders: &[OrderPrim], nonce: i64, expires_after: Option<i64>) -> Outcome {
        let body = match self.build_body(orders, nonce, expires_after) {
            Ok(b) => b,
            Err(e) => return Outcome::NotSent(e),
        };
        match self.net.post(&self.url, "application/json", body.as_bytes()) {
            Ok(r) => Outcome::Sent {
                status: r.status,
                body: r.body,
                retry_after: r.retry_after,
                tx_hash: None,
                tx_info: None,
            },
            Err(e) => Outcome::Unknown(e),
        }
    }
}

// --- C ABI -----------------------------------------------------------------------------------

/// Order primitives for [`HlPlaceOrders`]. All strings are NUL-terminated; `cloid` may be NULL.
#[repr(C)]
pub struct HlOrderPrim {
    pub asset: u32,
    pub is_buy: u8,
    pub reduce_only: u8,
    pub price: *const c_char,
    pub size: *const c_char,
    pub tif: *const c_char,
    pub cloid: *const c_char,
}

unsafe fn to_prim<'a>(p: &'a HlOrderPrim) -> Option<OrderPrim<'a>> {
    let s = |ptr: *const c_char| -> Option<&'a str> {
        if ptr.is_null() {
            None
        } else {
            unsafe { std::ffi::CStr::from_ptr(ptr) }.to_str().ok()
        }
    };
    Some(OrderPrim {
        asset: p.asset,
        is_buy: p.is_buy != 0,
        reduce_only: p.reduce_only != 0,
        price: s(p.price)?,
        size: s(p.size)?,
        tif: s(p.tif)?,
        cloid: if p.cloid.is_null() { None } else { Some(s(p.cloid)?) },
    })
}

fn set_err(out_err: *mut *mut c_char, msg: String) {
    if !out_err.is_null() {
        unsafe { *out_err = cstring(msg) };
    }
}

/// Creates a client bound to one wallet and one pooled connection. Returns NULL on failure with
/// the reason in `*out_err` (free with `Free`). `vault_address`, `proxy_url` and `ca_pem_path` may be
/// NULL; `timeout_ms` / `idle_ms` of 0 select the defaults. Free the handle with [`HlClientFree`].
///
/// # Safety
/// String arguments must be NULL or valid NUL-terminated strings; `out_err` NULL or writable.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn HlClientNew(
    base_url: *const c_char,
    private_key_hex: *const c_char,
    is_mainnet: i32,
    vault_address: *const c_char,
    proxy_url: *const c_char,
    ca_pem_path: *const c_char,
    timeout_ms: i64,
    idle_ms: i64,
    out_err: *mut *mut c_char,
) -> *mut c_void {
    let r = std::panic::catch_unwind(|| -> Result<HlClient, String> {
        let base = read_opt(base_url).ok_or("base_url is required")?;
        let key = read_opt(private_key_hex).ok_or("private_key_hex is required")?;
        let net = Transport::shared(
            read_opt(proxy_url).as_deref(),
            read_opt(ca_pem_path).as_deref(),
            timeout_ms.max(0) as u64,
            idle_ms.max(0) as u64,
        )?;
        HlClient::new(&base, &key, is_mainnet != 0, read_opt(vault_address).as_deref(), net)
    });
    match r {
        Ok(Ok(c)) => Box::into_raw(Box::new(c)) as *mut c_void,
        Ok(Err(e)) => {
            set_err(out_err, e);
            std::ptr::null_mut()
        }
        Err(_) => {
            set_err(out_err, "internal error creating client".into());
            std::ptr::null_mut()
        }
    }
}

/// # Safety
/// `client` must come from [`HlClientNew`] and not be used afterwards.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn HlClientFree(client: *mut c_void) {
    if !client.is_null() {
        drop(unsafe { Box::from_raw(client as *mut HlClient) });
    }
}

/// Sign and POST `n` limit orders as one `order` action (one signature, one request).
/// `nonce` is required (the caller owns nonce allocation).
///
/// # Safety
/// `client` must be a live handle; `orders` must point to `n` valid [`HlOrderPrim`]s.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn HlPlaceOrders(
    client: *const c_void,
    orders: *const HlOrderPrim,
    n: usize,
    nonce: i64,
    expires_after: i64,
    has_expires_after: u8,
) -> OneShotResponse {
    guard(|| {
        if client.is_null() {
            return Outcome::NotSent("null client".into());
        }
        if orders.is_null() || n == 0 {
            return Outcome::NotSent("at least one order is required".into());
        }
        let client = unsafe { &*(client as *const HlClient) };
        let raw = unsafe { std::slice::from_raw_parts(orders, n) };
        let mut prims = Vec::with_capacity(n);
        for p in raw {
            match unsafe { to_prim(p) } {
                Some(p) => prims.push(p),
                None => return Outcome::NotSent("order has a NULL or non-UTF-8 string field".into()),
            }
        }
        client.place_orders(&prims, nonce, (has_expires_after != 0).then_some(expires_after))
    })
}

/// Single-order convenience over [`HlPlaceOrders`], avoiding the struct for scalar callers.
///
/// # Safety
/// `client` must be a live handle; string arguments NUL-terminated (`cloid` may be NULL).
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn HlPlaceOrder(
    client: *const c_void,
    asset: u32,
    is_buy: u8,
    price: *const c_char,
    size: *const c_char,
    reduce_only: u8,
    tif: *const c_char,
    cloid: *const c_char,
    nonce: i64,
    expires_after: i64,
    has_expires_after: u8,
) -> OneShotResponse {
    let prim = HlOrderPrim { asset, is_buy, reduce_only, price, size, tif, cloid };
    unsafe { HlPlaceOrders(client, &prim, 1, nonce, expires_after, has_expires_after) }
}
