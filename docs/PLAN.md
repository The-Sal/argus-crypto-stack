# Argus Crypto Stack (ACS) — Plan

**Goal:** A single Rust `cdylib` (`argus_crypto_stack`) that replaces, with a drop-in C ABI:
1. Lighter's vendored Go shared libraries (`Argus/argus/perpetuals/lighter/signers/lighter-signer-{darwin-arm64,darwin-amd64,linux-amd64,linux-arm64}.{dylib,so}`) loaded via ctypes in `Argus/argus/perpetuals/lighter/_signer.py`.
2. Hyperliquid's pure-Python EIP-712 signing (`eth_account` + `keccak` + `msgpack`) in `Argus/argus/perpetuals/hyper/exchange.py`.

Crates are allowed. 

---

## ⚡ MAJOR PIVOT (2026-10-24): verified Rust port already exists

Web research + direct source inspection found an existing **from-scratch Rust port of lighter-go**
with byte-for-byte parity tests against Go-generated vectors. We build on it instead of hand-porting
~8k lines of Poseidon2/ECgFp5/Schnorr.

| Crate | Version | Covers | Verified |
|---|---|---|---|
| `lighters` | 0.1.1 | Tx types, validation, hashing, JSON, KeyManager, TxClient, auth token, all L2 tx types | ships `tests/vectors.json` (21 vectors) + `tests/parity.rs` + `tests/signing.rs` asserting **hash and JSON byte-equality vs Go** |
| `poseidon-hash` | 0.1.4 | Goldilocks field, Poseidon2 (WIDTH=12 RATE=8 OUT=4 D=7 RF=8 RP=22), Fp5 quintic ext, `hash_to_quintic_extension` | used by `lighters`; mirrors `elliottech/poseidon_crypto` |
| `goldilocks-crypto` | 0.1.2 | ECgFp5 curve, 320-bit/5-limb scalar field (N/N0I/R2/T632 match Go exactly), Schnorr | `lighters` parity tests |

**Verified directly in source (not just docs):**
- `goldilocks-crypto::ScalarField` is genuinely `[u64; 5]` (320-bit) with the exact Go constants
  (`N[0]=0xE80FD996948BFFE1`, `N0I=0xD78BEF72057B7BDF`, `R2`, `T632`). The crate README's "256-bit/4-limb"
  note is stale documentation; the code is correct.
- `lighters` JSON for `CreateOrder` is byte-identical to Go:
  `{"AccountIndex":1,"ApiKeyIndex":0,"MarketIndex":0,...,"Sig":"<base64 80B>","L2TxAttributes":null}`
  (PascalCase, flattened `OrderInfo`, base64 `Sig`, embedded attr map → `null` when absent).
- Both crates are **unaudited** — this is why the differential harness (Stage 4) is mandatory.

**Consequence:** the previously-planned hand-port stages (Goldilocks, GFp5, Poseidon2, ECgFp5, Schnorr,
tx types) are **dropped**. Remaining work is the C ABI shim, Hyperliquid, verification, and packaging.

---

## Ground-truth sources (read these, don't guess)

| What | Where |
|---|---|
| C ABI Argus expects (structs + argtypes) | `Argus/argus/perpetuals/lighter/_signer.py` |
| Go sharedlib to replicate symbol-for-symbol | `lighter-go/sharedlib/main.go` |
| **Differential oracle (the real acceptance test)** | `Argus/argus/perpetuals/lighter/signers/lighter-signer-darwin-arm64.dylib` (+3 others) |
| Go source of the crypto | `github.com/elliottech/poseidon_crypto` (clone at `/Users/Salman/x/poseidon_crypto`) |
| Portable engine | `lighters` 0.1.1 + `poseidon-hash` 0.1.4 + `goldilocks-crypto` 0.1.2 (in `~/.cargo/registry/src/...`) |
| Argus Hyperliquid EIP-712 scheme | `Argus/argus/perpetuals/hyper/exchange.py` (`_L1_DOMAIN`, `_L1_TYPES`, `action_hash`, `sign_action`) |
| Existing offline tests (must keep passing) | `Argus/tests/test_lighter_signer.py`, `Argus/tests/test_hyper_exchange.py` |

## Scope (what Argus actually calls)

**Lighter — required C exports** (from `_signer.py`):
`GenerateAPIKey`, `CreateClient`, `CheckClient`, `SignCreateOrder`, `SignCancelOrder`,
`SignCancelAllOrders`, `SignUpdateLeverage`, `CreateAuthToken`, `Free`.
Everything else in the Go sharedlib is out of scope.

**Hyperliquid — new C exports** (no Go counterpart; designed here):
- `HlActionHash(action_packed, len, nonce, vault_addr, expires_after, has_expires_after, out_hash: *mut u8) -> i32` (0 = ok; see README for the final ABI) — keccak-256 over `msgpack(action) || nonce(8B BE) || vault-tag || [0x00 + expires(8B BE)]`.
- `HlSignAction(private_key_hex, action_packed, len, nonce, vault_addr, expires_after, has_expires_after, is_mainnet) -> HlSig{r:[u8;32], s:[u8;32], v:u8}` — EIP-712 `Agent` (source "a"/"b", connectionId) under domain `{name:"Exchange", version:"1", chainId:1337, verifyingContract:0x0..0}`, then signing of the EIP-712 digest directly (**no** EIP-191 personal prefix, matching `eth_account.encode_typed_data`); deterministic RFC6979 secp256k1.

## Key wire/ABI facts (gotchas that break silently)

- Keys are `0x`-prefixed hex from `GenerateAPIKey`; Python strips 0x before `CreateClient`.
- `SignedTxResponse = {txType: u8, txInfo: *c_char, txHash: *c_char, messageToSign: *c_char, err: *c_char}`; all strings `C.CString` (NUL-terminated UTF-8), freed by `Free`.
- `txInfo` JSON must match Go's serde-equivalent layout (see verified `CreateOrder` sample above). `lighters` already does this.
- 80-byte schnorr sig = `S(40B LE) || E(40B LE)`; JSON base64 of those 80 bytes.
- Default expiry = `DEFAULT_EXPIRE_MS` (599_000 ms), matching Go `DefaultExpireTime`.
- Auth token: `"{expiry_unix}:{accountIndex}:{apiKeyIndex}:{hex(sig)}"` — `lighters::TxClient::auth_token`.
- Hyperliquid r/s must be fixed-width 32-byte hex with 0x prefix.

## Architecture

```
argus-crypto-stack/
├── Cargo.toml                 cdylib + rlib; deps: lighters(no default), secp256k1, tiny-keccak, ureq, libc
├── src/
│   ├── lib.rs                 module tree
│   ├── lighter/
│   │   ├── client.rs          global registry Mutex<HashMap<(u8,i64), Arc<TxClient>>> + default-client rules
│   │   ├── http.rs            ureq impl of lighters::http::HttpClient (get_api_key for CheckClient)
│   │   └── abi.rs             extern "C" exports (exact _signer.py signatures) + Free
│   └── hyper/
│       ├── eip712.rs          domain separator + Agent struct hash (hand-rolled, 4 fields)
│       ├── secp.rs            secp256k1 RFC6979 + recovery id
│       └── abi.rs             HlActionHash / HlSignAction
├── tests/                     Rust tests (Hl pinned vectors etc.)
└── tools/
    └── diff_harness.py        Python ctypes: Go dylib vs Rust cdylib, byte-compare txInfo/txHash, verify sigs
```

**Validation strategy (the whole game):**
1. **Independent differential harness** (`tools/diff_harness.py`): load the vendored Go dylib and the Rust cdylib side by side via ctypes; for ≥100 randomized cases per Argus tx type (CreateOrder/CancelOrder/CancelAllOrders/UpdateLeverage) with fixed nonces/expiry, assert `txInfo` JSON and `txHash` are byte-identical. This is the acceptance gate, independent of the crate's shipped vectors.
2. **Existing Argus tests** `test_lighter_signer.py` / `test_hyper_exchange.py` must pass with the Rust lib swapped in (offline).
3. **Hyperliquid**: RFC6979 deterministic → Rust r/s/v must be byte-identical to `eth_account`; pin vectors + a recovery round-trip test.

---

## Stages

### Stage 0 — Recon + scaffolding ✅
- [x] Read Go sharedlib ABI, tx client, tx types, Argus `_signer.py` + Hyperliquid exchange
- [x] Clone `poseidon_crypto` to `/Users/Salman/x/poseidon_crypto`
- [x] Workspace `Cargo.toml` (cdylib+rlib, edition 2024), skeleton modules compile
- [x] Research → discovered `lighters`/`poseidon-hash`/`goldilocks-crypto`
- [x] Source-verify scalar field (5-limb) + JSON parity + locate vendored Go oracle

### Stage 1 — Dependencies + engine wiring ✅
- [x] `Cargo.toml`: `lighters = { version = "0.1.1", default-features = false }`; `secp256k1` (recovery), `tiny-keccak`, `ureq`, `libc`
- [x] Sanity: reproduce a `lighters` parity vector (hash+JSON) from our own code (`tests/engine_sanity.rs`)
- [x] Crypto parity: Go sigvector pubkey + fixed-nonce signature (`tests/crypto_parity.rs`)

### Stage 2 — Lighter C ABI ✅
- [x] `lighter/client.rs`: registry keyed `(apiKeyIndex u8, accountIndex i64)`, default-client rule `apiKeyIndex==255`, `CreateClient` local validation
- [x] `lighter/http.rs`: ureq `HttpClient` impl (`get_api_key` → CheckClient)
- [x] `lighter/abi.rs`: all 9 exports + `Free`; exact `_signer.py` argtypes; `catch_unwind` → err string
- [x] Wire tx attributes (skipNonce, integrator*, selfTrade*, cancelAllMarketIndex) exactly as the Go sharedlib does
- [x] txHash = `SignedHash` (hex of the 40-byte message hash, no 0x) — matches Go `ethCommon.Bytes2Hex`
- [x] **Differential harness: 507/507 cases byte-identical** vs the vendored Go dylib

### Stage 3 — Hyperliquid module ✅
- [x] `hyper/eip712.rs`: keccak domain separator + `Agent` struct hash
- [x] `hyper/secp.rs`: secp256k1 RFC6979 recoverable sign of the EIP-712 digest (no personal prefix — `encode_typed_data` uses version `0x01`), v=27/28
- [x] `hyper/abi.rs`: `HlActionHash`, `HlSignAction` (vault/expires logic identical to Python)
- [x] **`tools/hl_diff_harness.py`: 120/120 cases byte-identical to `eth_account`**

### Stage 4 — Differential validation ✅
- [x] `tools/diff_harness.py`: Go dylib vs Rust cdylib, 507 cases, byte-compare txInfo/txHash (auto-falls back to the Go backup in `~/.cache/argus-crypto-stack/` after install)
- [x] Swap in Argus: `tests/test_lighter_signer.py` → 4 passed with ACS
- [x] `tools/hl_diff_harness.py`: `eth_account` vs ACS, 120 cases, byte-compare hash+r/s/v
- [x] Wired `hyper/exchange.py` → `HlSignAction` via new `hyper/_signer.py` (native, Python fallback): `tests/test_hyper_native_signer.py` (7) + `test_hyper_exchange.py` (108) pass; 376 perpetuals/hyper/lighter tests pass
- [x] Updated `Argus/docs/perpetuals/SIGNING.md`

### Stage 5 — Packaging ✅
- [x] Release profile (LTO, opt-level 3, strip); all four targets built
- [x] Cross-built darwin-amd64, linux-amd64, linux-arm64 via `cargo zigbuild`; verified ELF/Mach-O + all 11 exported symbols (the 6 one-shot symbols from Stage 6 are darwin-arm64 only)
- [x] `tools/build_and_install.sh` installs all four over Argus's vendored signer files
- [x] README: build, ABI docs, provenance/audit caveat, cross-build verification status

### Stage 6 — One-shot sign+POST (Rust side only) ✅
- [x] `src/oneshot/{net,ffi,hl,lighter}.rs`: pooled `ureq` transport (proxy `socks5h`, private CA, timeout, idle age), `OneShotResponse` with `kind` 0/1/2
- [x] Hyperliquid: `HlClientNew/Free`, `HlPlaceOrders`, `HlPlaceOrder` (hand-rolled msgpack, golden vectors from the Python path)
- [x] Lighter: `LighterSetTransport`, `LighterCreateOrder` (+ `sign_create_order_core` refactor of `SignCreateOrder`; `quote_plus`-compatible form encoding)
- [x] `tests/oneshot.rs` (12 tests) + `tests/vectors/hl_oneshot.json`; diff harnesses still 507/507 and 120/120
- [x] `docs/ONESHOT.md`, README section
- [ ] Python bindings + `exchange.py` wiring (explicitly deferred; Argus untouched; then update `Argus/docs/perpetuals/SIGNING.md`)
- [ ] Deferred ops: Lighter `sendTxBatch`, cancels (both venues), `updateLeverage`, other HL actions
- [ ] Cross-build + run the six new symbols on linux/darwin-amd64
- [ ] Investigate direct-TLS overhead (~190 µs vs ~57 µs floor) in the Rust client

### Remaining / future
- [ ] Runtime-verify the Linux `.so` on a Linux host (only structural checks done here)
- [ ] Audit or vendor the `lighters`/`poseidon-hash`/`goldilocks-crypto` crates
- [ ] Optionally add FastAPI/WASM or a Python wheel for the HL wrapper

---

## Status log
- 2026-10-24: Recon complete. **Pivot:** adopted verified `lighters` 0.1.1 (+`poseidon-hash`, `goldilocks-crypto`) instead of hand-porting. Vendored Go dylibs located for differential testing.
- 2026-10-24: Stage 1–3 complete. Lighter ABI: 507/507 differential cases byte-identical. Hyperliquid: 120/120 byte-identical to `eth_account`. Argus `test_lighter_signer.py` passes with ACS swapped in.
- 2026-10-24: Stage 4–5 complete. Wired Hyperliquid into Argus (`hyper/_signer.py` + `exchange.py`, native with Python fallback); added `tests/test_hyper_native_signer.py`. Cross-built all four platforms and installed over the vendored Go dylibs via `tools/build_and_install.sh`. Updated `SIGNING.md`. Full perpetuals/hyper/lighter suite: 376 passed.
- 2026-10-24: Stage 6 (Rust only): one-shot sign+POST for Hyperliquid (single + batch place) and Lighter (create order), 17 exports total. `cargo test` 12 new tests pass; diff harnesses unchanged. ctypes run via TLS+SOCKS5 mock: HL body identical to Argus `place_order`, 81 us vs 474 us; Lighter 156 us vs 542 us. Argus Python untouched.
