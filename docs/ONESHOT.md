# One-shot calls: sign + POST in a single native call

> **Status:** implemented in ACS (Rust) and covered by `cargo test`. **Not yet wired into Argus**:
> no Python binding or `exchange.py` change exists yet, and `Argus/docs/perpetuals/SIGNING.md` is
> intentionally not updated until that wiring lands.

## Why

Once signing is native (`HlSignAction` ≈ 16 µs, Lighter sign ≈ 90 µs), the dominant per-order cost
in Argus is the Python HTTP stack (`requests`, ≈ 330 µs warm) plus the glue around it. A one-shot
call takes the order *primitives* and does everything up to and including the POST in Rust,
returning the HTTP response:

```
prims ─▶ msgpack ─▶ keccak ─▶ EIP-712 sign ─▶ JSON body ─▶ pooled HTTP POST ─▶ (status, body)      # Hyperliquid
prims ─▶ sign (same core as SignCreateOrder) ─▶ form-encode ─▶ pooled HTTP POST ─▶ (status, body)  # Lighter
```

## What is and is not in scope

| Concern | Owner |
|---|---|
| price/size rounding, asset-id / market resolution, validation of business rules | **caller (Python)** — unchanged |
| **nonce allocation** (Lighter counter + lock, Hyperliquid ms nonce) | **caller** — `nonce` is a required argument; Lighter rejects `-1` |
| signing, msgpack/JSON/form encoding, HTTP POST, connection pooling | **ACS** |
| interpreting the response (`status == "ok"`, `code == 200`, 429 → `RateLimitError`) | **caller** |

Deferred (not implemented): Lighter `sendTxBatch`, cancels (either venue), `updateLeverage`, and
Hyperliquid non-`order` actions. Hyperliquid *batch place* is implemented.

## Result struct (both venues)

```c
typedef struct {
    int32_t kind;          // see below
    int32_t http_status;   // valid when kind == 0
    char*   body;          // response body, valid when kind == 0
    char*   retry_after;   // Retry-After header or NULL
    char*   tx_hash;       // Lighter: signer's tx hash; Hyperliquid: NULL
    char*   tx_info;       // Lighter: exact tx_info JSON that was POSTed; Hyperliquid: NULL
    char*   err;           // set when kind != 0
} OneShotResponse;
```

**Freeing:** every non-NULL `char*` field is a heap C string released with the library's existing
`Free(ptr)`. Free each field individually. NULL means absent.

| `kind` | Meaning | What a nonce-managing caller does |
|---|---|---|
| `0` OK | An HTTP response was received (any status, incl. 4xx/5xx). Inspect `http_status`/`body`. | Nonce is consumed. Treat non-2xx / venue rejection like today (Lighter resets its counter). |
| `1` NOT_SENT | Rejected locally: bad input, unknown client, signing failure. **Nothing left the process.** | Safe to release the nonce. |
| `2` UNKNOWN | Transport failure mid-flight (connect/TLS/proxy/timeout/read). The venue may or may not have the request. | Fate unknown: re-read the venue nonce (Lighter `_reset_nonce`). |

HTTP status is deliberately *not* an error: a `429` is `kind 0, http_status 429, retry_after "3"` so
the caller can raise its own `RateLimitError`.

## Hyperliquid

```c
typedef struct HlClient HlClient;   // opaque

// One wallet + one pooled connection (+ optional proxy / private CA). NULL on failure, reason in *out_err.
HlClient* HlClientNew(const char* base_url, const char* private_key_hex, int32_t is_mainnet,
                      const char* vault_address /*NULL ok*/, const char* proxy_url /*NULL ok*/,
                      const char* ca_pem_path /*NULL ok*/, int64_t timeout_ms /*0=10000*/,
                      int64_t idle_ms /*0=30000*/, char** out_err);
void HlClientFree(HlClient*);

typedef struct { uint32_t asset; uint8_t is_buy; uint8_t reduce_only;
                 const char* price; const char* size; const char* tif; const char* cloid /*NULL ok*/; } HlOrderPrim;

// One `order` action: one signature, one request, n >= 1 orders (caller enforces the venue's batch cap, Argus uses 40).
OneShotResponse HlPlaceOrders(const HlClient*, const HlOrderPrim* orders, size_t n,
                              int64_t nonce, int64_t expires_after, uint8_t has_expires_after);

// Scalar convenience for n == 1.
OneShotResponse HlPlaceOrder(const HlClient*, uint32_t asset, uint8_t is_buy, const char* price,
                             const char* size, uint8_t reduce_only, const char* tif,
                             const char* cloid, int64_t nonce, int64_t expires_after, uint8_t has_expires_after);
```

* `price`/`size` are the **wire strings** Argus already produces (`_to_wire_number(rounded)`); `tif` is
  `Gtc`/`Ioc`/`Alo` (anything else is `kind 1`). `nonce` must be ≥ 0.
* The request body is `{action, nonce, signature:{r,s,v}, vaultAddress, expiresAfter}` and the msgpack
  key order (`a b p s r t [c]`; `type orders grouping`) matches `exchange.py`, because key order is part
  of the signed hash.
* `is_mainnet` selects the EIP-712 source tag (`a`/`b`), exactly like `HlSignAction`; Argus derives it
  from the base URL.
* The signing key is parsed once in `HlClientNew`. The handle is `Send + Sync` and may be shared across
  threads (the pool is internally synchronised). Create one per wallet.

## Lighter

```c
// Optional. Without it a direct (no proxy) transport with default timeouts is created on first use.
// Replaces the client's transport, dropping its pooled connections. Returns NULL or an error string.
char* LighterSetTransport(int32_t api_key_index, int64_t account_index, const char* proxy_url,
                          const char* ca_pem_path, int64_t timeout_ms, int64_t idle_ms);

// Same 19 arguments as SignCreateOrder (nonce must be >= 0; -1 is rejected with kind 1).
OneShotResponse LighterCreateOrder(/* ... identical to SignCreateOrder ... */);
```

* The client (key, chain id, endpoint) is the one registered by `CreateClient`; the POST goes to
  `<CreateClient url>/api/v1/sendTx` as `application/x-www-form-urlencoded` with `tx_type` and `tx_info`.
* Signing uses the *same internal function* as `SignCreateOrder` (`sign_create_order_core`), so the
  transaction is identical; `tx_info` returned in the response is exactly what was sent.
* **Form encoding matters.** `tx_info` carries a base64 signature containing `+`, `/`, `=`. ACS
  encodes like Python's `quote_plus` (what `requests` uses), and the tests assert the wire form decodes
  back to the reported `tx_info` over 300 signatures.
* Lighter keeps nonces strictly ordered per key. The one-shot call does **not** serialise anything: the
  caller must keep holding its submit lock from allocation through the call, as `_serialized` does today.

## Transport details

* One pooled `ureq` agent per `HlClient` / per Lighter `(api_key_index, account_index)`. A new agent per
  request would throw away the warm connection, which is most of the win.
* `proxy_url`: use **`socks5h://host:port`** (hostname resolved by the proxy, as Argus's `requests` setup
  does). Plain `socks5://` resolves locally and, in testing, failed for `localhost` (IPv6 vs an IPv4-only
  listener).
* `idle_ms` is how long an idle pooled connection is kept (default 30 s). Keep it **at or below** the
  venue/proxy idle timeout; a connection that expired server-side costs a reconnect on the next order
  (see the July 2026 leg-miss RCA / Argus v1.0.8 keepalive fix). `timeout_ms` is a global per-request timeout.
* `ca_pem_path` replaces the bundled web roots; for private CAs and tests only.
* Calls are blocking. Under ctypes the GIL is released for their duration.

## Measured performance

Loopback mock (Go) with TLS and a local SOCKS5 hop standing in for wireproxy; warm connection; Apple M4
Pro; p50 of 3,000 calls per row; **single run**, so treat as indicative (the earlier 10-round / 20k-sample
campaign measured the same path at 446 µs vs 85 µs, p50 across rounds 432–458 vs 84–87 µs).

| Venue | Argus path today (native sign + `requests`) | One-shot | Saved |
|---|---:|---:|---:|
| Hyperliquid `place_order` | 474 µs | **81 µs** | ≈ 390 µs (5.9x) |
| Lighter create order (`SignCreateOrder` + `requests.post`) | 542 µs | **156 µs** | ≈ 390 µs (3.5x) |

Not modelled: real network latency and the WireGuard tunnel (both add equal cost to either path).
Cold connections are dominated by the TLS+proxy handshake (≈ 1.2–1.9 ms regardless of client), so the
one-shot gain there is smaller (≈ 0.7 ms).

**Known issue:** direct-to-server TLS with the Rust client measured ≈ 190 µs warm vs a ≈ 57 µs floor
from a Python `http.client` on the same server, while the same call through the SOCKS hop took ≈ 85 µs.
Cause not identified (suspected `ureq`/`rustls` write pattern). Production goes through the proxy, so it
is not on the hot path, but a direct-TLS deployment should be measured first.

## Verification

```sh
cargo test --release                 # includes tests/oneshot.rs (12 tests, in-process HTTP mock)
GO_SIGNER_LIB=/path/to/go-signer.dylib "$ARGUS_DIR/.venv/bin/python" tools/diff_harness.py      # 507/507, still byte-identical after the sign_create_order_core refactor
"$ARGUS_DIR/.venv/bin/python" tools/hl_diff_harness.py                                          # 120/120
```

`tests/oneshot.rs` covers:

* **Hyperliquid golden vectors** (`tests/vectors/hl_oneshot.json`), generated by the pure-Python Argus
  path (`msgpack.packb(use_bin_type=True)` + `eth_account`): msgpack bytes are identical and the request
  body is semantically identical (parsed JSON equal, including signature). Cases: with/without cloid,
  asset ids needing `uint8`/`uint16`/`uint32` encodings (incl. HIP-3 ids ≥ 110000), a 20-order batch
  (`array16` header), vault + `expiresAfter`, and strings needing JSON escaping.
* Lighter: wire form ⇔ reported `tx_info`; `+ / =` escaping actually exercised; the one-shot tx equals
  `SignCreateOrder`'s output (minus the randomised `Sig`/`SignedHash` and call-time `ExpiredAt`).
* Local rejection (`kind 1`) sends nothing; connect failure is `kind 2`; `429` + `Retry-After` is `kind 0`;
  40 / 30 consecutive calls reuse exactly one TCP connection; the C ABI round-trips including `out_err`.

Also run end to end through `ctypes` against a TLS + SOCKS5 mock: the Hyperliquid request body equals what
Argus's own `place_order` sends, and the Lighter wire `tx_info` equals the reported one. The Linux `.so`
and darwin-amd64 builds of the six new symbols have **not** been built or run (only darwin-arm64).
