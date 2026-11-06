//! One-shot (sign + POST) tests against a self-contained plain-HTTP mock.
//!
//! Hyperliquid: golden vectors in `tests/vectors/hl_oneshot.json` were produced by the existing
//! pure-Python Argus path (`msgpack.packb(use_bin_type=True)` + `eth_account`), so a pass means the
//! native request body is semantically identical to what Argus sends today (same msgpack bytes,
//! same signature). Lighter signatures are randomised, so there we check what is on the wire:
//! the form decodes to exactly the `tx_info` the call reports it sent.

use std::collections::HashMap;
use std::ffi::{c_char, CStr, CString};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use argus_crypto_stack::lighter::abi::{CreateClient, Free, GenerateAPIKey, SignCreateOrder};
use argus_crypto_stack::oneshot::ffi::{Outcome, OneShotResponse, KIND_NOT_SENT, KIND_OK, KIND_UNKNOWN};
use argus_crypto_stack::oneshot::hl::{
    encode_orders_msgpack, HlClient, HlClientFree, HlClientNew, HlOrderPrim, HlPlaceOrder, HlPlaceOrders,
    OrderPrim,
};
use argus_crypto_stack::oneshot::lighter::{form_encode, LighterCreateOrder, LighterSetTransport};
use argus_crypto_stack::oneshot::net::Transport;
use serde_json::Value;

// --- mock server -----------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct Req {
    path: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

struct Mock {
    base: String,
    reqs: Arc<Mutex<Vec<Req>>>,
    conns: Arc<AtomicUsize>,
}

impl Mock {
    fn last(&self) -> Req {
        self.reqs.lock().unwrap().last().cloned().expect("a request")
    }
    fn count(&self) -> usize {
        self.reqs.lock().unwrap().len()
    }
}

fn serve(conn: TcpStream, reqs: Arc<Mutex<Vec<Req>>>, status: u16, body: &'static str, extra: &'static str) {
    let mut w = conn.try_clone().unwrap();
    let mut r = BufReader::new(conn);
    loop {
        let mut line = String::new();
        if r.read_line(&mut line).unwrap_or(0) == 0 {
            return;
        }
        let path = line.split_whitespace().nth(1).unwrap_or("").to_string();
        let mut headers = HashMap::new();
        loop {
            let mut h = String::new();
            r.read_line(&mut h).unwrap();
            if h == "\r\n" || h.is_empty() {
                break;
            }
            if let Some((k, v)) = h.split_once(':') {
                headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
            }
        }
        let len: usize = headers.get("content-length").and_then(|v| v.parse().ok()).unwrap_or(0);
        let mut buf = vec![0u8; len];
        r.read_exact(&mut buf).unwrap();
        reqs.lock().unwrap().push(Req { path, headers, body: buf });
        let resp = format!(
            "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{extra}\r\n{body}",
            body.len()
        );
        if w.write_all(resp.as_bytes()).is_err() {
            return;
        }
    }
}

fn mock(status: u16, body: &'static str, extra: &'static str) -> Mock {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", l.local_addr().unwrap());
    let reqs = Arc::new(Mutex::new(Vec::new()));
    let conns = Arc::new(AtomicUsize::new(0));
    let (r2, c2) = (reqs.clone(), conns.clone());
    std::thread::spawn(move || {
        for conn in l.incoming().flatten() {
            c2.fetch_add(1, Ordering::SeqCst);
            let r3 = r2.clone();
            std::thread::spawn(move || serve(conn, r3, status, body, extra));
        }
    });
    Mock { base, reqs, conns }
}

const HL_OK: &str = r#"{"status":"ok","response":{"type":"order","data":{"statuses":[{"resting":{"oid":1}}]}}}"#;

fn net() -> Arc<Transport> {
    Transport::shared(None, None, 0, 0).unwrap()
}

// --- Hyperliquid -----------------------------------------------------------------------------

struct Case {
    name: String,
    is_mainnet: bool,
    nonce: i64,
    vault: Option<String>,
    expires: Option<i64>,
    owned: Vec<(u32, bool, String, String, bool, String, Option<String>)>,
    msgpack_hex: String,
    body: Value,
}

fn load_cases() -> (String, Vec<Case>) {
    let v: Value = serde_json::from_str(include_str!("vectors/hl_oneshot.json")).unwrap();
    let key = v["private_key"].as_str().unwrap().to_string();
    let cases = v["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| Case {
            name: c["name"].as_str().unwrap().into(),
            is_mainnet: c["is_mainnet"].as_bool().unwrap(),
            nonce: c["nonce"].as_i64().unwrap(),
            vault: c["vault"].as_str().map(String::from),
            expires: c["expires_after"].as_i64(),
            owned: c["orders"]
                .as_array()
                .unwrap()
                .iter()
                .map(|o| {
                    (
                        o["asset"].as_u64().unwrap() as u32,
                        o["is_buy"].as_bool().unwrap(),
                        o["price"].as_str().unwrap().into(),
                        o["size"].as_str().unwrap().into(),
                        o["reduce_only"].as_bool().unwrap(),
                        o["tif"].as_str().unwrap().into(),
                        o["cloid"].as_str().map(String::from),
                    )
                })
                .collect(),
            msgpack_hex: c["msgpack_hex"].as_str().unwrap().into(),
            body: c["body"].clone(),
        })
        .collect();
    (key, cases)
}

fn prims(c: &Case) -> Vec<OrderPrim<'_>> {
    c.owned
        .iter()
        .map(|(a, b, p, s, r, t, cl)| OrderPrim {
            asset: *a,
            is_buy: *b,
            reduce_only: *r,
            price: p,
            size: s,
            tif: t,
            cloid: cl.as_deref(),
        })
        .collect()
}

#[test]
fn hl_msgpack_matches_python_packer() {
    let (_, cases) = load_cases();
    for c in &cases {
        let got = encode_orders_msgpack(&prims(c)).unwrap();
        assert_eq!(hex::encode(got), c.msgpack_hex, "msgpack mismatch in case {}", c.name);
    }
}

#[test]
fn hl_request_body_matches_python_path() {
    let (key, cases) = load_cases();
    let m = mock(200, HL_OK, "");
    for c in &cases {
        let client = HlClient::new(&m.base, &key, c.is_mainnet, c.vault.as_deref(), net()).unwrap();
        let out = client.place_orders(&prims(c), c.nonce, c.expires);
        match out {
            Outcome::Sent { status, body, .. } => {
                assert_eq!(status, 200);
                assert_eq!(String::from_utf8(body).unwrap(), HL_OK);
            }
            other => panic!("case {}: {other:?}", c.name),
        }
        let req = m.last();
        assert_eq!(req.path, "/exchange");
        assert_eq!(req.headers["content-type"], "application/json");
        let sent: Value = serde_json::from_slice(&req.body).unwrap();
        assert_eq!(sent, c.body, "request body mismatch in case {}", c.name);
    }
}

#[test]
fn hl_rejects_bad_input_without_sending() {
    let (key, _) = load_cases();
    let m = mock(200, HL_OK, "");
    let client = HlClient::new(&m.base, &key, false, None, net()).unwrap();
    let good = OrderPrim { asset: 1, is_buy: true, reduce_only: false, price: "1", size: "1", tif: "Gtc", cloid: None };
    let bad_tif = OrderPrim { tif: "Fok", ..good };
    assert!(matches!(client.place_orders(&[], 1, None), Outcome::NotSent(_)));
    assert!(matches!(client.place_orders(&[bad_tif], 1, None), Outcome::NotSent(_)));
    assert!(matches!(client.place_orders(&[good], -1, None), Outcome::NotSent(_)));
    assert_eq!(m.count(), 0, "nothing may reach the wire");
    assert!(HlClient::new(&m.base, "not-hex", false, None, net()).is_err());
    assert!(HlClient::new(&m.base, &key, false, Some("0x1234"), net()).is_err());
}

#[test]
fn hl_surfaces_http_status_retry_after_and_transport_failure() {
    let (key, _) = load_cases();
    let limited = mock(429, r#"{"error":"slow down"}"#, "Retry-After: 3\r\n");
    let c = HlClient::new(&limited.base, &key, false, None, net()).unwrap();
    let o = OrderPrim { asset: 1, is_buy: true, reduce_only: false, price: "1", size: "1", tif: "Gtc", cloid: None };
    match c.place_orders(&[o], 1, None) {
        Outcome::Sent { status, retry_after, .. } => {
            assert_eq!(status, 429);
            assert_eq!(retry_after.as_deref(), Some("3"));
        }
        other => panic!("{other:?}"),
    }
    // Nothing is listening: connect failure is an UNKNOWN-fate transport error.
    let dead = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        format!("http://{}", l.local_addr().unwrap())
    };
    let c = HlClient::new(&dead, &key, false, None, net()).unwrap();
    assert!(matches!(c.place_orders(&[o], 1, None), Outcome::Unknown(_)));
}

#[test]
fn hl_reuses_one_keepalive_connection() {
    let (key, _) = load_cases();
    let m = mock(200, HL_OK, "");
    let c = HlClient::new(&m.base, &key, false, None, net()).unwrap();
    let o = OrderPrim { asset: 1, is_buy: true, reduce_only: false, price: "1", size: "1", tif: "Gtc", cloid: None };
    for n in 1..=40 {
        assert!(matches!(c.place_orders(&[o], n, None), Outcome::Sent { .. }));
    }
    assert_eq!(m.count(), 40);
    assert_eq!(m.conns.load(Ordering::SeqCst), 1, "all orders must share one pooled connection");
}

fn take(p: *mut c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    let s = unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned();
    Free(p as *mut _);
    Some(s)
}

fn drain(r: OneShotResponse) -> (i32, i32, Option<String>, Option<String>, Option<String>, Option<String>, Option<String>) {
    (r.kind, r.http_status, take(r.body), take(r.retry_after), take(r.tx_hash), take(r.tx_info), take(r.err))
}

#[test]
fn hl_c_abi_roundtrip() {
    let (key, cases) = load_cases();
    let c = &cases[0];
    let m = mock(200, HL_OK, "");
    let (base, k) = (CString::new(m.base.clone()).unwrap(), CString::new(key).unwrap());
    let mut err: *mut c_char = std::ptr::null_mut();
    let h = unsafe {
        HlClientNew(base.as_ptr(), k.as_ptr(), c.is_mainnet as i32, std::ptr::null(), std::ptr::null(), std::ptr::null(), 0, 0, &mut err)
    };
    assert!(!h.is_null() && err.is_null());

    // scalar single-order entry point
    let (p, s, t, cl) = (
        CString::new(c.owned[0].2.clone()).unwrap(),
        CString::new(c.owned[0].3.clone()).unwrap(),
        CString::new(c.owned[0].5.clone()).unwrap(),
        CString::new(c.owned[0].6.clone().unwrap()).unwrap(),
    );
    let r = unsafe { HlPlaceOrder(h, c.owned[0].0, 1, p.as_ptr(), s.as_ptr(), 0, t.as_ptr(), cl.as_ptr(), c.nonce, 0, 0) };
    let (kind, status, body, _, hash, info, e) = drain(r);
    assert_eq!((kind, status), (KIND_OK, 200));
    assert_eq!(body.as_deref(), Some(HL_OK));
    assert!(hash.is_none() && info.is_none() && e.is_none());
    let sent: Value = serde_json::from_slice(&m.last().body).unwrap();
    assert_eq!(sent, c.body);

    // struct-array entry point with a NULL string is rejected locally
    let bad = HlOrderPrim { asset: 1, is_buy: 1, reduce_only: 0, price: std::ptr::null(), size: s.as_ptr(), tif: t.as_ptr(), cloid: std::ptr::null() };
    let before = m.count();
    let (kind, _, _, _, _, _, e) = drain(unsafe { HlPlaceOrders(h, &bad, 1, 1, 0, 0) });
    assert_eq!(kind, KIND_NOT_SENT);
    assert!(e.is_some());
    assert_eq!(m.count(), before);

    // bad client construction reports through out_err
    let badkey = CString::new("zz").unwrap();
    let h2 = unsafe {
        HlClientNew(base.as_ptr(), badkey.as_ptr(), 0, std::ptr::null(), std::ptr::null(), std::ptr::null(), 0, 0, &mut err)
    };
    assert!(h2.is_null());
    assert!(take(err).is_some());
    unsafe { HlClientFree(h) };
}

// --- Lighter ---------------------------------------------------------------------------------

const LIGHTER_OK: &str = r#"{"code":200,"message":"success","tx_hash":"abc"}"#;

fn form_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' => {
                out.push(u8::from_str_radix(&s[i + 1..i + 3], 16).unwrap());
                i += 2;
            }
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8(out).unwrap()
}

fn parse_form(body: &[u8]) -> HashMap<String, String> {
    String::from_utf8(body.to_vec())
        .unwrap()
        .split('&')
        .map(|kv| {
            let (k, v) = kv.split_once('=').unwrap();
            (k.to_string(), form_decode(v))
        })
        .collect()
}

fn new_lighter_client(url: &str, account: i64) {
    let key = GenerateAPIKey();
    let private = take(key.private_key).unwrap();
    take(key.public_key);
    assert!(take(key.err).is_none());
    let (u, k) = (CString::new(url).unwrap(), CString::new(private).unwrap());
    let err = CreateClient(u.as_ptr(), k.as_ptr(), 304, 3, account);
    assert!(take(err).is_none());
}

#[allow(clippy::too_many_arguments)]
fn create(nonce: i64, account: i64, client_order_index: i64) -> OneShotResponse {
    LighterCreateOrder(0, client_order_index, 1000, 50_000, 0, 0, 1, 0, 0, 99_999_999, 0, 0, 0, 0, 0, 0, nonce, 3, account)
}

#[test]
fn form_encode_matches_python_quote_plus() {
    assert_eq!(form_encode("a b+c/d=e~f_g.h-i"), "a+b%2Bc%2Fd%3De~f_g.h-i");
    assert_eq!(form_encode("{\"a\":1}"), "%7B%22a%22%3A1%7D");
    assert_eq!(form_encode("é"), "%C3%A9");
}

#[test]
fn lighter_wire_form_decodes_to_reported_tx_info() {
    let m = mock(200, LIGHTER_OK, "");
    new_lighter_client(&m.base, 9001);
    let mut special = 0;
    for i in 0..300 {
        let (kind, status, body, _, hash, info, err) = drain(create(1000 + i, 9001, 1 + i));
        assert_eq!((kind, status), (KIND_OK, 200), "{err:?}");
        assert_eq!(body.as_deref(), Some(LIGHTER_OK));
        let (hash, info) = (hash.unwrap(), info.unwrap());
        assert!(!hash.is_empty());

        let req = m.last();
        assert_eq!(req.path, "/api/v1/sendTx");
        assert_eq!(req.headers["content-type"], "application/x-www-form-urlencoded");
        let wire = String::from_utf8(req.body.clone()).unwrap();
        // Exactly the two field separators may carry '=', and nothing may carry a raw '+' or '/'.
        assert_eq!(wire.matches('=').count(), 2, "unescaped '=' in {wire}");
        assert!(!wire.contains('+') && !wire.contains('/'), "unescaped +// in {wire}");
        let form = parse_form(&req.body);
        assert_eq!(form["tx_info"], info, "decoded wire tx_info must equal the reported tx_info");
        let v: Value = serde_json::from_str(&info).expect("tx_info is JSON");
        assert_eq!(v["Nonce"].as_i64(), Some(1000 + i));
        assert_eq!(v["AccountIndex"].as_i64(), Some(9001));
        if info.contains('+') || info.contains('/') || info.contains('=') {
            special += 1;
        }
    }
    assert!(special > 0, "never exercised a tx_info containing + / = (test would not catch an encoding bug)");
}

#[test]
fn lighter_one_shot_signs_the_same_tx_as_sign_create_order() {
    let m = mock(200, LIGHTER_OK, "");
    new_lighter_client(&m.base, 9002);
    let resp = drain(create(77, 9002, 5));
    let sent_info: Value = serde_json::from_str(resp.5.as_deref().unwrap()).unwrap();
    let s = SignCreateOrder(0, 5, 1000, 50_000, 0, 0, 1, 0, 0, 99_999_999, 0, 0, 0, 0, 0, 0, 77, 3, 9002);
    let signed_info: Value = serde_json::from_str(&take(s.tx_info).unwrap()).unwrap();
    take(s.tx_hash);
    take(s.message_to_sign);
    take(s.err);
    // Schnorr signatures are randomised; every other field (and ExpiredAt is call-time based) must agree.
    let strip = |mut v: Value| {
        for k in ["Sig", "SignedHash", "ExpiredAt"] {
            v.as_object_mut().unwrap().remove(k);
        }
        v
    };
    assert_eq!(strip(sent_info), strip(signed_info));
}

#[test]
fn lighter_rejects_unsendable_calls_locally() {
    let m = mock(200, LIGHTER_OK, "");
    new_lighter_client(&m.base, 9003);
    let (kind, _, _, _, _, _, err) = drain(create(-1, 9003, 1));
    assert_eq!(kind, KIND_NOT_SENT);
    assert!(err.unwrap().contains("nonce"));
    let (kind, ..) = drain(create(5, 424242, 1)); // no such client
    assert_eq!(kind, KIND_NOT_SENT);
    assert_eq!(m.count(), 0);
}

#[test]
fn lighter_429_unknown_fate_and_keepalive() {
    let limited = mock(429, r#"{"code":429}"#, "Retry-After: 7\r\n");
    new_lighter_client(&limited.base, 9004);
    let (kind, status, _, retry, hash, ..) = drain(create(1, 9004, 1));
    assert_eq!((kind, status), (KIND_OK, 429));
    assert_eq!(retry.as_deref(), Some("7"));
    assert!(hash.is_some(), "tx_hash is reported even for a venue rejection");

    let dead = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        format!("http://{}", l.local_addr().unwrap())
    };
    new_lighter_client(&dead, 9005);
    assert_eq!(drain(create(1, 9005, 1)).0, KIND_UNKNOWN);

    let m = mock(200, LIGHTER_OK, "");
    new_lighter_client(&m.base, 9006);
    for i in 0..30 {
        assert_eq!(drain(create(i, 9006, 1 + i)).0, KIND_OK);
    }
    assert_eq!(m.conns.load(Ordering::SeqCst), 1, "all orders must share one pooled connection");
}

#[test]
fn lighter_set_transport_validates_and_replaces() {
    new_lighter_client("http://127.0.0.1:1", 9007);
    let bad = CString::new("not a url").unwrap();
    let e = unsafe { LighterSetTransport(3, 9007, bad.as_ptr(), std::ptr::null(), 0, 0) };
    assert!(take(e).is_some(), "an invalid proxy URL must be reported");
    let missing = CString::new("/nonexistent/ca.pem").unwrap();
    let e = unsafe { LighterSetTransport(3, 9007, std::ptr::null(), missing.as_ptr(), 0, 0) };
    assert!(take(e).is_some(), "a missing CA file must be reported");
    let e = unsafe { LighterSetTransport(3, 9007, std::ptr::null(), std::ptr::null(), 5_000, 10_000) };
    assert!(take(e).is_none());
}
