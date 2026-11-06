//! Argus Crypto Stack — Rust drop-in replacement for:
//! 1. Lighter's vendored Go signer shared libraries (Poseidon2/Goldilocks/ECgFp5 Schnorr)
//! 2. Hyperliquid's pure-Python EIP-712 signing (secp256k1 + keccak)
//!
//! Lighter crypto + transaction types are delegated to the `lighters` crate, a
//! from-scratch Rust port of `lighter-go` with byte-for-byte parity tests against
//! Go-generated vectors. This crate supplies the C ABI that Argus's
//! `perpetuals/lighter/_signer.py` ctypes wrapper expects, plus native
//! Hyperliquid EIP-712 signing.
//!
//! See PLAN.md for the full design and stage tracking.

pub mod lighter {
    pub mod abi;
    pub mod client;
    pub mod http;
}

pub mod hyper {
    pub mod abi;
    pub mod eip712;
    pub mod secp;
}

pub mod oneshot {
    pub mod ffi;
    pub mod hl;
    pub mod lighter;
    pub mod net;
}
