# Argus Crypto Stack (ACS)

A single Rust `cdylib` that replaces two crypto dependencies in
[Argus](../Argus):

1. **Lighter** — the vendored Go signer shared library (`lighter-signer-*.dylib`/`.so`)
   loaded via ctypes in `argus/perpetuals/lighter/_signer.py`. ACS exports the
   **exact same C symbols and struct layouts**, so it is a drop-in replacement.
2. **Hyperliquid** — the pure-Python EIP-712 signing (`eth_account` + `keccak` +
   `msgpack`) in `argus/perpetuals/hyper/exchange.py`. ACS computes the action
   hash and the ECDSA signature natively.

## Provenance (read this before trusting it)

The Lighter engine is [`lighters`](https://crates.io/crates/lighters) 0.1.1, a
from-scratch Rust port of `lighter-go`, built on
[`poseidon-hash`](https://crates.io/crates/poseidon-hash) 0.1.4 (Goldilocks +
Poseidon2 + Fp5 quintic extension) and
[`goldilocks-crypto`](https://crates.io/crates/goldilocks-crypto) 0.1.2 (ECgFp5 +
Schnorr). Those crates ship Go-generated parity vectors, and ACS verifies them
again independently:

- `cargo test` — reproduces Go transaction hashes/JSON and a fixed-nonce Schnorr
  signature (`tests/engine_sanity.rs`, `tests/crypto_parity.rs`).
- `tools/diff_harness.py` — **507/507** randomized cases byte-identical to the
  *vendored Go dylib* (tx type, tx info JSON minus the randomized signature,
  tx hash) for create/cancel/cancel-all/leverage + attributes.
- `tools/hl_diff_harness.py` — **120/120** Hyperliquid cases byte-identical to
  `eth_account` (action hash + r/s/v), across vault/expires/mainnet variants.

⚠️ `lighters`, `poseidon-hash` and `goldilocks-crypto` are **unaudited**. The
differential harnesses above are the safety net; run them before shipping.

## Build

```sh
cargo build --release
# -> target/release/libargus_crypto_stack.dylib   (macOS)
# -> target/release/libargus_crypto_stack.so      (Linux)
```

To build every platform Argus ships and install them over the vendored signer
files (requires `cargo-zigbuild` + the four rustup targets):

```sh
./tools/build_and_install.sh          # or: ARGUS_DIR=/path/to/Argus ./tools/build_and_install.sh
```

This overwrites `lighter-signer-{darwin,linux}-{arm64,amd64}.*` (same filenames,
so `_signer.py` loads them unchanged) and keeps a copy of the original Go dylib
in `~/.cache/argus-crypto-stack/` (override with `GO_SIGNER_BACKUP`) for the
differential harness. Or install one target manually:

```sh
cp target/release/libargus_crypto_stack.dylib \
   ../Argus/argus/perpetuals/lighter/signers/lighter-signer-darwin-arm64.dylib
```

## C ABI

### Lighter (matches `_signer.py`)

| Export | Signature |
|---|---|
| `GenerateAPIKey` | `() -> ApiKeyResponse{privateKey, publicKey, err}` (0x-hex, 40-byte LE) |
| `CreateClient` | `(url, privkey, chainId: i32, apiKeyIndex: i32, accountIndex: i64) -> *char err` |
| `CheckClient` | `(apiKeyIndex: i32, accountIndex: i64) -> *char err` (GET `/api/v1/apikeys`) |
| `SignCreateOrder` | 19 args (see `src/lighter/abi.rs`) `-> SignedTxResponse` |
| `SignCancelOrder` | `(marketIndex: i32, orderIndex: i64, skipNonce: u8, nonce: i64, apiKeyIndex: i32, accountIndex: i64)` |
| `SignCancelAllOrders` | `(timeInForce: i32, timestampMs: i64, cancelAllMarketIndex: i32, skipNonce: u8, nonce: i64, apiKeyIndex: i32, accountIndex: i64)` |
| `SignUpdateLeverage` | `(marketIndex: i32, initialMarginFraction: i32, marginMode: i32, skipNonce: u8, nonce: i64, apiKeyIndex: i32, accountIndex: i64)` |
| `CreateAuthToken` | `(deadline: i64, apiKeyIndex: i32, accountIndex: i64) -> StrOrErr` |
| `Free` | `(ptr) -> ()` |

Structs (`#[repr(C)]`):

```c
typedef struct { char* privateKey; char* publicKey; char* err; } ApiKeyResponse;
typedef struct { char* str; char* err; } StrOrErr;
typedef struct { uint8_t txType; char* txInfo; char* txHash; char* messageToSign; char* err; } SignedTxResponse;
```

All strings are heap C strings freed with `Free`; panics are converted to `err`.

### Hyperliquid (new)

```c
typedef struct { uint8_t r[32]; uint8_t s[32]; uint8_t v; char* err; } HlSig;

// Writes the 32-byte keccak action hash to out_hash. 0 on success.
int HlActionHash(const uint8_t* action_packed, size_t len, int64_t nonce,
                 const char* vault_address /* NULL/empty = none */,
                 int64_t expires_after, uint8_t has_expires_after,
                 uint8_t* out_hash);

HlSig HlSignAction(const char* private_key_hex,
                   const uint8_t* action_packed, size_t len, int64_t nonce,
                   const char* vault_address, int64_t expires_after,
                   uint8_t has_expires_after, int32_t is_mainnet);
```

`action_packed` is the caller's `msgpack(action)` (serialization, not crypto).
`v` is 27/28; `r`/`s` are raw 32-byte big-endian integers. Argus renders them as
fixed-width `0x`-hex.

## Verification

```sh
cargo test                                   # Go vectors (hash/JSON/signature)
python3 tools/diff_harness.py                # Lighter vs vendored Go dylib
"$ARGUS_DIR/.venv/bin/python" tools/hl_diff_harness.py   # Hyperliquid vs eth_account
```

After `build_and_install.sh` the vendored file *is* ACS; `diff_harness.py` then
automatically falls back to that Go backup, or use
`GO_SIGNER_LIB=/path/to/go-signer.dylib`.

The Argus-side integration is covered by `tests/test_hyper_native_signer.py`
(native path vs the pure-Python path, byte-for-byte) and the existing
`tests/test_lighter_signer.py`.

### Cross-build verification status

Only `darwin-arm64` is exercised at runtime on this host. The Linux `.so` files
are cross-built with `cargo-zigbuild` from the same sources and were checked for
platform (`ELF`) and the original 11 exported symbols, but not run in a Linux container. The six one-shot
symbols added later (17 total) have only been built and run on darwin-arm64.

## One-shot calls (sign + POST in one native call)

ACS also exports `HlClientNew`/`HlClientFree`/`HlPlaceOrders`/`HlPlaceOrder` and
`LighterSetTransport`/`LighterCreateOrder`, which take order primitives and do everything up to and
including the HTTP POST in Rust, returning the response (`OneShotResponse`: `kind`, `http_status`, `body`,
`retry_after`, `tx_hash`, `tx_info`, `err`). The caller still owns rounding, asset resolution and **nonce
allocation**. Measured ≈ 390 µs faster per order than native-sign + `requests` on a warm connection through
TLS + a SOCKS5 hop. Full ABI, error-kind semantics, transport options, benchmarks and the known direct-TLS
issue: [`docs/ONESHOT.md`](docs/ONESHOT.md). **Not wired into Argus yet** (no Python changes).

## Argus integration

- **Lighter**: no Python changes — overwrite the bundled dylib (see Build).
- **Hyperliquid**: already wired — `argus/perpetuals/hyper/_signer.py` is a ctypes
  wrapper around `HlSignAction`, used by `HyperLiquidExchange.sign_action` with a
  pure-Python fallback. The action dict is still packed with
  `msgpack.packb(action, use_bin_type=True)` before the call.

See `PLAN.md` for the full staged design and status.
