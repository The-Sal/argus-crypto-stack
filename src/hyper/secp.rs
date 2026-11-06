//! secp256k1 signing for Hyperliquid.
//!
//! Mirrors `eth_account`'s `Account.sign_message(encode_typed_data(...))`.
//! For typed data, `encode_typed_data` produces a `SignableMessage` with
//! `version = 0x01`, `header = domainSeparator`, `body = structHash`, so
//! `_hash_eip191_message` yields `keccak(0x1901 || domainSeparator || structHash)`
//! — i.e. the EIP-712 digest itself, with **no** personal-message prefix. It is
//! then signed with deterministic (RFC 6979) recoverable ECDSA; `v` is 27/28.

use secp256k1::{Message, Secp256k1, SecretKey};

pub struct Signature {
    pub r: [u8; 32],
    pub s: [u8; 32],
    /// 27 or 28 (Ethereum's `v`, not the raw recovery id 0..3).
    pub v: u8,
}

/// Signs an EIP-712 digest exactly as `eth_account` does for typed data.
pub fn sign_eip712_digest(private_key: &[u8], digest: &[u8; 32]) -> Result<Signature, String> {
    sign_digest(private_key, digest)
}

/// Deterministic recoverable ECDSA over a 32-byte digest.
pub fn sign_digest(private_key: &[u8], digest: &[u8; 32]) -> Result<Signature, String> {
    let secret = SecretKey::from_slice(private_key).map_err(|e| e.to_string())?;
    let msg = Message::from_digest(*digest);
    let secp = Secp256k1::new();
    let sig = secp.sign_ecdsa_recoverable(&msg, &secret);
    let (recid, compact) = sig.serialize_compact();

    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&compact[0..32]);
    s.copy_from_slice(&compact[32..64]);
    let v = 27 + i32::from(recid) as u8;
    Ok(Signature { r, s, v })
}

/// Parses an optional `0x`-prefixed hex private key into raw bytes.
pub fn parse_private_key(hex_str: &str) -> Result<Vec<u8>, String> {
    let trimmed = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(trimmed).map_err(|e| format!("invalid private key hex: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!(
            "invalid private key length: expected 32 bytes, got {}",
            bytes.len()
        ));
    }
    Ok(bytes)
}
