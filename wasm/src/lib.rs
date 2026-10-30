//! Thin wasm-bindgen wrapper around `sealdrop-core` for the browser.
//!
//! All cryptography stays in Rust; JavaScript only moves bytes around.
//! Errors cross into JS as a generic message (see `sealdrop_core::Error`),
//! never with secret-dependent detail.
//!
//! Secrets passed in from JS (`secret: &[u8]`) are copied into Rust types that
//! wipe themselves on drop. Copies that JavaScript keeps are outside our
//! control; the web client keeps them only in memory, never in storage.

#![forbid(unsafe_code)]

use sealdrop_core::{
    file,
    identity::{self, SecretIdentity},
    keywrap::{self, KdfKind},
    xwing,
};
use wasm_bindgen::prelude::*;

fn js(e: sealdrop_core::Error) -> JsError {
    JsError::new(&e.to_string())
}

/// New random identity: 64 secret bytes (X-Wing seed || ML-DSA seed).
#[wasm_bindgen(js_name = generateIdentity)]
pub fn generate_identity() -> Result<Vec<u8>, JsError> {
    Ok(SecretIdentity::generate().map_err(js)?.to_bytes().to_vec())
}

/// X-Wing public key (1216 bytes) for a 64 byte secret identity.
#[wasm_bindgen(js_name = publicKemKey)]
pub fn public_kem_key(secret: &[u8]) -> Result<Vec<u8>, JsError> {
    Ok(SecretIdentity::from_bytes(secret).map_err(js)?.public().kem_pk.to_vec())
}

/// ML-DSA-65 verifying key (1952 bytes) for a 64 byte secret identity.
#[wasm_bindgen(js_name = publicSigKey)]
pub fn public_sig_key(secret: &[u8]) -> Result<Vec<u8>, JsError> {
    Ok(SecretIdentity::from_bytes(secret).map_err(js)?.public().sig_vk.to_vec())
}

/// SHA3-256 of a public key, for display and comparison.
#[wasm_bindgen]
pub fn fingerprint(public_key: &[u8]) -> Vec<u8> {
    identity::fingerprint(public_key).to_vec()
}

/// Encrypt for `recipient_kem_pk` and sign with `sender_secret`.
#[wasm_bindgen]
pub fn seal(plaintext: &[u8], recipient_kem_pk: &[u8], sender_secret: &[u8]) -> Result<Vec<u8>, JsError> {
    let pk: [u8; xwing::PUBLIC_KEY_LEN] = recipient_kem_pk
        .try_into()
        .map_err(|_| js(sealdrop_core::Error::InvalidKey))?;
    let sender = SecretIdentity::from_bytes(sender_secret).map_err(js)?;
    file::seal(plaintext, &pk, &sender).map_err(js)
}

/// Verify the sender signature, then decrypt.
#[wasm_bindgen]
pub fn open(sealed: &[u8], recipient_secret: &[u8], sender_sig_vk: &[u8]) -> Result<Vec<u8>, JsError> {
    let me = SecretIdentity::from_bytes(recipient_secret).map_err(js)?;
    file::open(sealed, &me, sender_sig_vk).map_err(js)
}

/// Sender fingerprint from the (unauthenticated) header: tells the client
/// which public key to fetch. `open` then authenticates it.
#[wasm_bindgen(js_name = senderFingerprint)]
pub fn sender_fingerprint(sealed: &[u8]) -> Result<Vec<u8>, JsError> {
    Ok(file::peek_header(sealed).map_err(js)?.sender_fingerprint.to_vec())
}

/// Wrap the secret identity with a key derived from passkey PRF output.
#[wasm_bindgen(js_name = wrapWithPrf)]
pub fn wrap_with_prf(prf_output: &[u8], secret: &[u8], username: &str) -> Result<Vec<u8>, JsError> {
    let key = keywrap::wrapping_key_from_prf(prf_output).map_err(js)?;
    let id = SecretIdentity::from_bytes(secret).map_err(js)?;
    keywrap::wrap(&key, KdfKind::Prf, &[0; keywrap::SALT_LEN], &id, username.as_bytes()).map_err(js)
}

/// Fallback (weaker): wrap with an Argon2id key derived from a passphrase.
#[wasm_bindgen(js_name = wrapWithPassphrase)]
pub fn wrap_with_passphrase(passphrase: &str, secret: &[u8], username: &str) -> Result<Vec<u8>, JsError> {
    let salt = keywrap::new_salt().map_err(js)?;
    let key = keywrap::wrapping_key_from_passphrase(passphrase.as_bytes(), &salt).map_err(js)?;
    let id = SecretIdentity::from_bytes(secret).map_err(js)?;
    keywrap::wrap(&key, KdfKind::Passphrase, &salt, &id, username.as_bytes()).map_err(js)
}

/// 1 = PRF, 2 = passphrase.
#[wasm_bindgen(js_name = wrappedKdf)]
pub fn wrapped_kdf(blob: &[u8]) -> Result<u8, JsError> {
    Ok(keywrap::blob_kdf(blob).map_err(js)?.0 as u8)
}

#[wasm_bindgen(js_name = unwrapWithPrf)]
pub fn unwrap_with_prf(prf_output: &[u8], blob: &[u8], username: &str) -> Result<Vec<u8>, JsError> {
    let key = keywrap::wrapping_key_from_prf(prf_output).map_err(js)?;
    let id = keywrap::unwrap(&key, blob, username.as_bytes()).map_err(js)?;
    Ok(id.to_bytes().to_vec())
}

#[wasm_bindgen(js_name = unwrapWithPassphrase)]
pub fn unwrap_with_passphrase(passphrase: &str, blob: &[u8], username: &str) -> Result<Vec<u8>, JsError> {
    let (_, salt) = keywrap::blob_kdf(blob).map_err(js)?;
    let key = keywrap::wrapping_key_from_passphrase(passphrase.as_bytes(), &salt).map_err(js)?;
    let id = keywrap::unwrap(&key, blob, username.as_bytes()).map_err(js)?;
    Ok(id.to_bytes().to_vec())
}
