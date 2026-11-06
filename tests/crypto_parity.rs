//! Independent crypto parity checks against Go-generated vectors
//! (`lighter-go/cmd/sigvector`).
//!
//! These pin the Schnorr signature and public-key derivation to the Go
//! reference, complementing the ABI-level differential harness
//! (`tools/diff_harness.py`) which cannot compare the randomized signature
//! bytes directly.

use lighters::signer::{self, KeyManager};

// From lighter-go/cmd/sigvector (embedded in lighters' tests/sigvector.json).
const PRIV_KEY: &str = "07000000000000000300000000000000000000000000000000000000000000000000000000000000";
const PUB_KEY: &str = "48d4615592bf39d71889f5127c7710c36912b733a1f8f32cb9446a7aec4e34461348642d459cbc77";
const MSG_HASH: &str = "01000000000000000200000000000000030000000000000004000000000000000500000000000000";
const NONCE: &str = "09000000000000000000000000000000050000000000000000000000000000000000000000000000";
const SIG: &str = "a90169cde0aa539d74553bcdccd969925519370da180f17c2374f9448d857d7d3dd342894fe83770e321927a894dadef5932badf109a622dbd07be130e22e522f1c58ec27e05e9458071b476bfa1e708";

#[test]
fn pubkey_derivation_matches_go() {
    let km = KeyManager::from_hex(PRIV_KEY).unwrap();
    assert_eq!(hex::encode(km.public_key_bytes()), PUB_KEY);
}

#[test]
fn deterministic_signature_matches_go() {
    let km = KeyManager::from_hex(PRIV_KEY).unwrap();
    let msg = hex::decode(MSG_HASH).unwrap();
    let nonce = hex::decode(NONCE).unwrap();
    let sig = km.sign_with_nonce(&msg, &nonce).unwrap();
    assert_eq!(hex::encode(sig), SIG);
}

#[test]
fn random_signature_verifies() {
    let km = KeyManager::from_hex(PRIV_KEY).unwrap();
    let msg = hex::decode(MSG_HASH).unwrap();
    let sig = km.sign(&msg).unwrap();
    assert!(km.verify(&msg, &sig));
    assert!(signer::verify(&msg, &sig, &km.public_key_bytes()));
}
