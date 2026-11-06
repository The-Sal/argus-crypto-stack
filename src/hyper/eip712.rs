//! Minimal EIP-712 hashing for Hyperliquid's phantom-agent L1 signing scheme.
//!
//! Only one struct is ever signed (`Agent`), so this is hand-rolled rather than
//! pulling in a generic EIP-712 crate.
//!
//! Domain: `{ name: "Exchange", version: "1", chainId: 1337, verifyingContract: 0x0 }`
//! Types:  `Agent { string source; bytes32 connectionId; }`

use tiny_keccak::{Hasher, Keccak};

/// keccak-256.
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    let mut out = [0u8; 32];
    hasher.update(data);
    hasher.finalize(&mut out);
    out
}

const DOMAIN_TYPE: &str =
    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";
const AGENT_TYPE: &str = "Agent(string source,bytes32 connectionId)";
const DOMAIN_NAME: &str = "Exchange";
const DOMAIN_VERSION: &str = "1";
const DOMAIN_CHAIN_ID: u64 = 1337;

fn u256_from_u64(value: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&value.to_be_bytes());
    out
}

/// EIP-712 domain separator for Hyperliquid's Exchange domain.
pub fn domain_separator() -> [u8; 32] {
    let mut buf = Vec::with_capacity(5 * 32);
    buf.extend_from_slice(&keccak256(DOMAIN_TYPE.as_bytes()));
    buf.extend_from_slice(&keccak256(DOMAIN_NAME.as_bytes()));
    buf.extend_from_slice(&keccak256(DOMAIN_VERSION.as_bytes()));
    buf.extend_from_slice(&u256_from_u64(DOMAIN_CHAIN_ID));
    buf.extend_from_slice(&[0u8; 32]); // verifyingContract = 0x0000..00 (address, left-padded)
    keccak256(&buf)
}

/// EIP-712 struct hash of `Agent { source, connectionId }`.
pub fn agent_struct_hash(source: &str, connection_id: &[u8; 32]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(3 * 32);
    buf.extend_from_slice(&keccak256(AGENT_TYPE.as_bytes()));
    buf.extend_from_slice(&keccak256(source.as_bytes()));
    buf.extend_from_slice(connection_id);
    keccak256(&buf)
}

/// The EIP-712 digest (`keccak(0x1901 || domainSeparator || structHash)`).
pub fn eip712_hash(source: &str, connection_id: &[u8; 32]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(66);
    buf.push(0x19);
    buf.push(0x01);
    buf.extend_from_slice(&domain_separator());
    buf.extend_from_slice(&agent_struct_hash(source, connection_id));
    keccak256(&buf)
}
