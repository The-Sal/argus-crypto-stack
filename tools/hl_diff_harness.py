#!/usr/bin/env python3
"""Hyperliquid differential harness: Python `eth_account` vs ACS Rust cdylib.

The current Argus path signs Hyperliquid actions in pure Python (msgpack +
eth_account EIP-712). ACS does it natively. This harness feeds identical packed
actions to both and requires byte-identical action hashes and ECDSA signatures
(RFC 6979 is deterministic, so r/s/v must match exactly).

Run with the Argus virtualenv (needs eth_account + msgpack):
    "$ARGUS_DIR/.venv/bin/python" tools/hl_diff_harness.py
"""
from __future__ import annotations

import ctypes
import os
import sys

import msgpack
from eth_account import Account
from eth_account.messages import encode_typed_data
from eth_utils import keccak

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUST_LIB = os.environ.get(
    "RUST_SIGNER_LIB", os.path.join(ROOT, "target/release/libargus_crypto_stack.dylib")
)

TEST_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
TEST_ADDRESS = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"

_L1_DOMAIN = {
    "name": "Exchange",
    "version": "1",
    "chainId": 1337,
    "verifyingContract": "0x0000000000000000000000000000000000000000",
}
_L1_TYPES = {
    "Agent": [
        {"name": "source", "type": "string"},
        {"name": "connectionId", "type": "bytes32"},
    ],
    "EIP712Domain": [
        {"name": "name", "type": "string"},
        {"name": "version", "type": "string"},
        {"name": "chainId", "type": "uint256"},
        {"name": "verifyingContract", "type": "address"},
    ],
}


def py_action_hash(action, nonce, vault_address=None, expires_after=None):
    data = msgpack.packb(action, use_bin_type=True)
    data += nonce.to_bytes(8, "big")
    if vault_address is None:
        data += b"\x00"
    else:
        hex_part = vault_address[2:] if vault_address.startswith("0x") else vault_address
        data += b"\x01" + bytes.fromhex(hex_part)
    if expires_after is not None:
        data += b"\x00" + expires_after.to_bytes(8, "big")
    return keccak(data)


def py_sign(action, nonce, is_mainnet, vault_address=None, expires_after=None):
    h = py_action_hash(action, nonce, vault_address, expires_after)
    payload = {
        "domain": _L1_DOMAIN,
        "types": _L1_TYPES,
        "primaryType": "Agent",
        "message": {"source": "a" if is_mainnet else "b", "connectionId": h},
    }
    signed = Account.from_key(TEST_KEY).sign_message(encode_typed_data(full_message=payload))
    return {
        "r": "0x" + format(signed["r"], "064x"),
        "s": "0x" + format(signed["s"], "064x"),
        "v": signed["v"],
    }


class HlSig(ctypes.Structure):
    _fields_ = [
        ("r", ctypes.c_uint8 * 32),
        ("s", ctypes.c_uint8 * 32),
        ("v", ctypes.c_uint8),
        ("err", ctypes.c_void_p),
    ]


def bind(lib):
    lib.HlActionHash.argtypes = [
        ctypes.c_void_p, ctypes.c_size_t, ctypes.c_longlong, ctypes.c_char_p,
        ctypes.c_longlong, ctypes.c_uint8, ctypes.c_void_p,
    ]
    lib.HlActionHash.restype = ctypes.c_int
    lib.HlSignAction.argtypes = [
        ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_longlong,
        ctypes.c_char_p, ctypes.c_longlong, ctypes.c_uint8, ctypes.c_int,
    ]
    lib.HlSignAction.restype = HlSig
    lib.Free.argtypes = [ctypes.c_void_p]
    lib.Free.restype = None
    return lib


ACTIONS = [
    {
        "type": "order",
        "orders": [
            {
                "a": 3, "b": True, "p": "50000.5", "s": "0.001", "r": False,
                "t": {"limit": {"tif": "Gtc"}},
                "c": "0x" + "ab" * 16,
            }
        ],
        "grouping": "na",
    },
    {"type": "cancel", "cancels": [{"a": 0, "o": 12345}]},
    {"type": "cancelByCloid", "cancels": [{"asset": 1, "cloid": "0x" + "cd" * 16}]},
    {"type": "updateLeverage", "asset": 0, "isCross": True, "leverage": 10},
    {
        "type": "order",
        "orders": [
            {"a": 0, "b": False, "p": "123.456", "s": "10", "r": True,
             "t": {"trigger": {"triggerPx": "100", "isMarket": True, "tpsl": "sl"}}}
        ],
        "grouping": "na",
    },
]

VAULTS = [None, "0x" + "12" * 20]
EXPIRES = [None, 1_700_000_123_456]


def main() -> int:
    if not os.path.exists(RUST_LIB):
        print(f"Rust cdylib not found at {RUST_LIB}; run `cargo build --release`")
        return 2
    lib = bind(ctypes.CDLL(RUST_LIB))

    failures = []
    checked = 0

    for ai, action in enumerate(ACTIONS):
        packed = msgpack.packb(action, use_bin_type=True)
        buf = ctypes.create_string_buffer(packed, len(packed))
        for nonce in (1, 1_700_000_000_000, 2**40):
            for vault in VAULTS:
                vb = vault.encode() if vault else None
                for expires in EXPIRES:
                    has_exp = 1 if expires is not None else 0
                    earg = expires if expires is not None else 0
                    for is_mainnet in (True, False):
                        label = f"action{ai} nonce={nonce} vault={vault} expires={expires} mainnet={is_mainnet}"

                        # action hash
                        out = ctypes.create_string_buffer(32)
                        rc = lib.HlActionHash(
                            buf, len(packed), nonce, vb, earg, has_exp, out
                        )
                        if rc != 0:
                            failures.append((label, "HlActionHash rc!=0", rc))
                            continue
                        expected_hash = py_action_hash(action, nonce, vault, expires)
                        if out.raw != expected_hash:
                            failures.append((label, expected_hash.hex(), out.raw.hex()))
                            continue

                        # signature
                        sig = lib.HlSignAction(
                            TEST_KEY.encode(), buf, len(packed), nonce, vb, earg,
                            has_exp, 1 if is_mainnet else 0,
                        )
                        err = None
                        if sig.err:
                            err = ctypes.cast(sig.err, ctypes.c_char_p).value.decode()
                            lib.Free(sig.err)
                        if err:
                            failures.append((label, "HlSignAction err", err))
                            continue

                        expected = py_sign(action, nonce, is_mainnet, vault, expires)
                        got = {
                            "r": "0x" + bytes(sig.r).hex(),
                            "s": "0x" + bytes(sig.s).hex(),
                            "v": int(sig.v),
                        }
                        if got != expected:
                            failures.append((label, expected, got))
                            continue
                        checked += 1

    print(f"checked {checked} Hyperliquid cases")
    if failures:
        print(f"\n{len(failures)} MISMATCHES:")
        for label, exp, got in failures[:20]:
            print(f"\n--- {label}\n  python: {exp}\n  rust  : {got}")
        return 1
    print("OK: all Hyperliquid signatures byte-identical to eth_account")
    return 0


if __name__ == "__main__":
    sys.exit(main())
