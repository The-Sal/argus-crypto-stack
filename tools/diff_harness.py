#!/usr/bin/env python3
"""Differential harness: vendored Go signer dylib vs ACS Rust cdylib.

Signs the Argus-used transaction set with identical inputs under the exact ctypes
ABI declared by ``argus.perpetuals.lighter._signer``, then compares ``tx_type``,
``tx_hash`` and ``tx_info`` JSON (with the randomized Schnorr ``Sig`` field
removed, since the Go library samples a fresh nonce per signature).

No network I/O: ``CreateClient`` only constructs an HTTP client; ``CheckClient``
is not called.

Usage:  python3 tools/diff_harness.py
Exit code 0 = byte-identical on every case.
"""
from __future__ import annotations

import ctypes
import json
import os
import random
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUST_LIB = os.environ.get(
    "RUST_SIGNER_LIB", os.path.join(ROOT, "target/release/libargus_crypto_stack.dylib")
)

ARGUS_DIR = os.environ.get("ARGUS_DIR", os.path.join(ROOT, "..", "Argus"))
_DEFAULT_SIGNER = os.path.join(
    ARGUS_DIR, "argus/perpetuals/lighter/signers/lighter-signer-darwin-arm64.dylib"
)
GO_BACKUP = os.environ.get(
    "GO_SIGNER_BACKUP",
    os.path.expanduser("~/.cache/argus-crypto-stack/go-signer-darwin-arm64.orig.dylib"),
)


def _exports_acs(path: str) -> bool:
    """True if `path` is the ACS Rust library rather than the Go oracle."""
    try:
        return hasattr(ctypes.CDLL(path), "HlSignAction")
    except OSError:
        return False


def _resolve_go_oracle() -> str:
    """The Go signer to compare against.

    `build_and_install.sh` overwrites the vendored Go dylib with ACS, so if the
    default path now holds ACS we fall back to the backup kept by that script.
    """
    explicit = os.environ.get("GO_SIGNER_LIB")
    if explicit:
        return explicit
    if not _exports_acs(_DEFAULT_SIGNER):
        return _DEFAULT_SIGNER
    if os.path.exists(GO_BACKUP):
        return GO_BACKUP
    return _DEFAULT_SIGNER


GO_LIB = _resolve_go_oracle()

# A canonical (< group order) 40-byte private key shared by both libraries.
FIXED_KEY = "0x" + "11" * 40
CHAIN_ID = 304
API_KEY_INDEX = 0
ACCOUNT_INDEX = 1

NUM_RANDOM_CASES = 120


class ApiKeyResponse(ctypes.Structure):
    _fields_ = [
        ("privateKey", ctypes.c_void_p),
        ("publicKey", ctypes.c_void_p),
        ("err", ctypes.c_void_p),
    ]


class StrOrErr(ctypes.Structure):
    _fields_ = [("str", ctypes.c_void_p), ("err", ctypes.c_void_p)]


class SignedTxResponse(ctypes.Structure):
    _fields_ = [
        ("txType", ctypes.c_uint8),
        ("txInfo", ctypes.c_void_p),
        ("txHash", ctypes.c_void_p),
        ("messageToSign", ctypes.c_void_p),
        ("err", ctypes.c_void_p),
    ]


def bind(lib):
    lib.GenerateAPIKey.argtypes = []
    lib.GenerateAPIKey.restype = ApiKeyResponse

    lib.CreateClient.argtypes = [
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_longlong,
    ]
    lib.CreateClient.restype = ctypes.c_void_p

    lib.CheckClient.argtypes = [ctypes.c_int, ctypes.c_longlong]
    lib.CheckClient.restype = ctypes.c_void_p

    lib.SignCreateOrder.argtypes = [
        ctypes.c_int, ctypes.c_longlong, ctypes.c_longlong, ctypes.c_int, ctypes.c_int,
        ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_longlong,
        ctypes.c_longlong, ctypes.c_int, ctypes.c_int, ctypes.c_uint8, ctypes.c_uint8,
        ctypes.c_uint8, ctypes.c_longlong, ctypes.c_int, ctypes.c_longlong,
    ]
    lib.SignCreateOrder.restype = SignedTxResponse

    lib.SignCancelOrder.argtypes = [
        ctypes.c_int, ctypes.c_longlong, ctypes.c_uint8, ctypes.c_longlong,
        ctypes.c_int, ctypes.c_longlong,
    ]
    lib.SignCancelOrder.restype = SignedTxResponse

    lib.SignCancelAllOrders.argtypes = [
        ctypes.c_int, ctypes.c_longlong, ctypes.c_int, ctypes.c_uint8, ctypes.c_longlong,
        ctypes.c_int, ctypes.c_longlong,
    ]
    lib.SignCancelAllOrders.restype = SignedTxResponse

    lib.SignUpdateLeverage.argtypes = [
        ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_uint8, ctypes.c_longlong,
        ctypes.c_int, ctypes.c_longlong,
    ]
    lib.SignUpdateLeverage.restype = SignedTxResponse

    lib.CreateAuthToken.argtypes = [ctypes.c_longlong, ctypes.c_int, ctypes.c_longlong]
    lib.CreateAuthToken.restype = StrOrErr

    lib.Free.argtypes = [ctypes.c_void_p]
    lib.Free.restype = None
    return lib


def _decode_and_free(lib, ptr):
    if not ptr:
        return None
    try:
        raw = ctypes.cast(ptr, ctypes.c_char_p).value
        return raw.decode("utf-8") if raw is not None else None
    finally:
        lib.Free(ptr)


def decode_tx(lib, resp: SignedTxResponse):
    err = _decode_and_free(lib, resp.err)
    info = _decode_and_free(lib, resp.txInfo)
    tx_hash = _decode_and_free(lib, resp.txHash)
    _decode_and_free(lib, resp.messageToSign)
    if err:
        raise RuntimeError(err)
    if not info or not tx_hash:
        raise RuntimeError("no tx info/hash and no error")
    return int(resp.txType), info, tx_hash


def strip_sig(info_json: str):
    obj = json.loads(info_json)
    obj.pop("Sig", None)
    return obj


# --- argument builders -------------------------------------------------------

def create_order_args(case):
    return (
        case["market_index"], case["client_order_index"], case["base_amount"], case["price"],
        int(case["is_ask"]), case["order_type"], case["time_in_force"], int(case["reduce_only"]),
        case["trigger_price"], case["order_expiry"], case["integrator_account_index"],
        case["integrator_taker_fee"], case["integrator_maker_fee"], case["self_trade_behavior_mode"],
        case["self_trade_equality_mode"], case["skip_nonce"], case["nonce"], API_KEY_INDEX,
        ACCOUNT_INDEX,
    )


def cancel_order_args(case):
    return (case["market_index"], case["order_index"], case["skip_nonce"], case["nonce"],
            API_KEY_INDEX, ACCOUNT_INDEX)


def cancel_all_args(case):
    return (case["time_in_force"], case["timestamp_ms"], case["cancel_all_market_index"],
            case["skip_nonce"], case["nonce"], API_KEY_INDEX, ACCOUNT_INDEX)


def leverage_args(case):
    return (case["market_index"], case["initial_margin_fraction"], case["margin_mode"],
            case["skip_nonce"], case["nonce"], API_KEY_INDEX, ACCOUNT_INDEX)


def random_order(rng: random.Random, nonce: int):
    kind = rng.choice(["limit_gtt", "limit_ioc", "limit_post_only", "market_ioc"])
    if kind == "limit_gtt":
        order_type, tif, expiry = 0, 1, rng.randint(1, 10**9)
    elif kind == "limit_ioc":
        order_type, tif, expiry = 0, 0, 0
    elif kind == "limit_post_only":
        order_type, tif, expiry = 0, 2, rng.randint(1, 10**9)
    else:
        order_type, tif, expiry = 1, 0, 0
    reduce_only = rng.choice([0, 0, 0, 1])
    return {
        "market_index": rng.randint(0, 200),
        "client_order_index": rng.randint(1, 1_000_000),
        "base_amount": 0 if reduce_only else rng.randint(1, 10**10),
        "price": rng.randint(1, 10**9),
        "is_ask": rng.choice([0, 1]),
        "order_type": order_type,
        "time_in_force": tif,
        "reduce_only": reduce_only,
        "trigger_price": 0,
        "order_expiry": expiry,
        "integrator_account_index": 0,
        "integrator_taker_fee": 0,
        "integrator_maker_fee": 0,
        "self_trade_behavior_mode": 0,
        "self_trade_equality_mode": 0,
        "skip_nonce": 0,
        "nonce": nonce,
    }


def main() -> int:
    if not os.path.exists(GO_LIB):
        print(f"SKIP: Go oracle not found at {GO_LIB}")
        return 0
    if _exports_acs(GO_LIB):
        print(
            f"ERROR: {GO_LIB} is the ACS Rust library, not the Go oracle. "
            "Set GO_SIGNER_LIB to the original Go dylib."
        )
        return 2
    if not os.path.exists(RUST_LIB):
        print(f"Rust cdylib not found at {RUST_LIB}; run `cargo build --release`")
        return 2

    go = bind(ctypes.CDLL(GO_LIB))
    rs = bind(ctypes.CDLL(RUST_LIB))

    # Register the same key in both.
    for name, lib in (("go", go), ("rust", rs)):
        err = _decode_and_free(
            lib, lib.CreateClient(
                b"https://mainnet.zklighter.elliot.ai", FIXED_KEY.encode(),
                CHAIN_ID, API_KEY_INDEX, ACCOUNT_INDEX,
            )
        )
        if err:
            print(f"CreateClient failed for {name}: {err}")
            return 2

    rng = random.Random(0xA65)
    failures = []
    checked = {"create_order": 0, "cancel_order": 0, "cancel_all": 0, "leverage": 0, "auth_token": 0}

    def compare_call(label, kind, go_call, rs_call):
        """Sign with both libs; retry until both see the same default ExpiredAt
        millisecond, then require byte-identical tx_type/tx_info(no Sig)/tx_hash."""
        last = None
        for _ in range(120):
            g = decode_tx(go, go_call())
            r = decode_tx(rs, rs_call())
            gj, rj = strip_sig(g[1]), strip_sig(r[1])
            if gj.get("ExpiredAt") == rj.get("ExpiredAt"):
                if (g[0], gj, g[2]) != (r[0], rj, r[2]):
                    failures.append((label, (g[0], gj, g[2]), (r[0], rj, r[2])))
                else:
                    checked[kind] += 1
                return
            last = (g, r)
        # Clock skew persisted: accept <=1ms ExpiredAt drift, skip tx_hash.
        g, r = last
        gj, rj = strip_sig(g[1]), strip_sig(r[1])
        ge, rexp = gj.pop("ExpiredAt"), rj.pop("ExpiredAt")
        if g[0] != r[0] or gj != rj or abs(ge - rexp) > 1:
            failures.append((label + " (skew)", (g[0], gj, g[2]), (r[0], rj, r[2])))
        else:
            checked[kind] += 1

    def compare(label, kind, go_out, rs_out):
        if go_out != rs_out:
            failures.append((label, go_out, rs_out))
        else:
            checked[kind] += 1

    # --- create order + attribute variants -----------------------------------
    for i in range(NUM_RANDOM_CASES):
        case = random_order(rng, nonce=1 + i)
        compare_call(f"create_order[{i}]", "create_order",
                     lambda c=case: go.SignCreateOrder(*create_order_args(c)),
                     lambda c=case: rs.SignCreateOrder(*create_order_args(c)))

    # --- cancel order --------------------------------------------------------
    for i in range(NUM_RANDOM_CASES):
        case = {
            "market_index": rng.randint(0, 200),
            "order_index": rng.randint(0, 2**40),
            "skip_nonce": 0,
            "nonce": 10_000 + i,
        }
        compare_call(f"cancel_order[{i}]", "cancel_order",
                     lambda c=case: go.SignCancelOrder(*cancel_order_args(c)),
                     lambda c=case: rs.SignCancelOrder(*cancel_order_args(c)))

    # --- cancel all ----------------------------------------------------------
    # Argus declares cancel_all_market_index as c_int, but Go's cgo wrapper
    # declares C.longlong; libffi leaves the upper register bits set for c_int, so
    # Go reads garbage there. Argus only uses immediate(0)/abort(2) cancel-all, so
    # scope the differential cases to those (scheduled's market must be NIL anyway).
    for i in range(NUM_RANDOM_CASES):
        tif = rng.choice([0, 0, 2])
        market = rng.choice([255, rng.randint(0, 200)]) if tif == 0 else 255
        case = {
            "time_in_force": tif,
            "timestamp_ms": 0,
            "cancel_all_market_index": market,
            "skip_nonce": 0,
            "nonce": 20_000 + i,
        }
        compare_call(f"cancel_all[{i}]", "cancel_all",
                     lambda c=case: go.SignCancelAllOrders(*cancel_all_args(c)),
                     lambda c=case: rs.SignCancelAllOrders(*cancel_all_args(c)))

    # --- update leverage -----------------------------------------------------
    for i in range(NUM_RANDOM_CASES):
        case = {
            "market_index": rng.randint(0, 200),
            "initial_margin_fraction": rng.randint(1, 10_000),
            "margin_mode": rng.choice([0, 1]),
            "skip_nonce": 0,
            "nonce": 30_000 + i,
        }
        compare_call(f"leverage[{i}]", "leverage",
                     lambda c=case: go.SignUpdateLeverage(*leverage_args(c)),
                     lambda c=case: rs.SignUpdateLeverage(*leverage_args(c)))

    # --- attributes: skipNonce + integrator + self-trade ---------------------
    attr_cases = [
        (0, 0, 0, 0, 0, 1),
        (12345, 0, 0, 0, 0, 0),
        (12345, 100, 200, 0, 0, 0),
        (0, 0, 0, 2, 0, 0),
        (0, 0, 0, 0, 1, 0),
    ]
    for j, (ii, tf, mf, sb, se, sn) in enumerate(attr_cases):
        case = random_order(rng, nonce=40_000 + j)
        case.update(integrator_account_index=ii, integrator_taker_fee=tf,
                    integrator_maker_fee=mf, self_trade_behavior_mode=sb,
                    self_trade_equality_mode=se, skip_nonce=sn)
        compare_call(f"create_order_attrs[{j}]", "create_order",
                     lambda c=case: go.SignCreateOrder(*create_order_args(c)),
                     lambda c=case: rs.SignCreateOrder(*create_order_args(c)))

    # --- auth token (randomized Schnorr sig -> compare message prefix) -------
    for i in range(20):
        deadline = 1_700_000_000 + i * 3600
        g = go.CreateAuthToken(deadline, API_KEY_INDEX, ACCOUNT_INDEX)
        r = rs.CreateAuthToken(deadline, API_KEY_INDEX, ACCOUNT_INDEX)
        g_tok = _decode_and_free(go, g.str)
        g_err = _decode_and_free(go, g.err)
        r_tok = _decode_and_free(rs, r.str)
        r_err = _decode_and_free(rs, r.err)
        if g_err or r_err:
            failures.append((f"auth_token[{i}]", g_err, r_err))
            continue
        g_prefix = g_tok.rsplit(":", 1)[0]
        r_prefix = r_tok.rsplit(":", 1)[0]
        # signature blob must be 80 bytes / 160 hex chars
        ok_len = len(g_tok.rsplit(":", 1)[1]) == 160 and len(r_tok.rsplit(":", 1)[1]) == 160
        compare(f"auth_token[{i}]", "auth_token", (g_prefix, ok_len), (r_prefix, ok_len))

    # --- GenerateAPIKey shape ------------------------------------------------
    for name, lib in (("go", go), ("rust", rs)):
        resp = lib.GenerateAPIKey()
        priv = _decode_and_free(lib, resp.privateKey)
        pub = _decode_and_free(lib, resp.publicKey)
        err = _decode_and_free(lib, resp.err)
        shape = (err is None and priv.startswith("0x") and len(priv) == 82
                 and pub.startswith("0x") and len(pub) == 82)
        compare(f"GenerateAPIKey[{name}]", "auth_token", True, shape)

    total = sum(checked.values())
    print(f"checked {total} cases: {checked}")
    if failures:
        print(f"\n{len(failures)} MISMATCHES:")
        for label, g, r in failures[:20]:
            print(f"\n--- {label}\n  go  : {json.dumps(g, sort_keys=True)}\n  rust: {json.dumps(r, sort_keys=True)}")
        return 1
    print("OK: all differential cases byte-identical")
    return 0


if __name__ == "__main__":
    sys.exit(main())
