//! Delegating one file to an AI agent (Milestone 7).
//!
//! The user's client recovers that file's key ([`crate::file::file_key`]) and
//! seals it to the agent's X-Wing public key. The agent can then open exactly
//! that file and nothing else: it never sees the user's private keys, and the
//! server only ever stores the wrapped key.
//!
//! ```text
//! blob    = "SDAK" || version (1) || X-Wing ciphertext (1120) || nonce (24) || AEAD(file key) (32 + 16)
//! key     = HKDF-SHA256(ss, info = "SealDrop v1 agent file key")
//! aad     = blob[0..1145] || context
//! context = SHA3-256(file header) || len(file_id) || file_id || len(agent_id) || agent_id
//! ```
//! The context binds the wrapped key to one file, its server id, and one
//! agent, so the server cannot swap wrapped keys between files or agents.

use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{Error, file, xwing};

pub const MAGIC: [u8; 4] = *b"SDAK";
pub const VERSION: u8 = 1;
const NONCE_LEN: usize = 24;
const PREFIX_LEN: usize = 4 + 1 + xwing::CIPHERTEXT_LEN + NONCE_LEN;
pub const BLOB_LEN: usize = PREFIX_LEN + 32 + 16;
const INFO: &[u8] = b"SealDrop v1 agent file key";

/// The binding context for one sealed file, its server id, and one agent.
pub fn context(sealed: &[u8], file_id: &str, agent_id: &str) -> Result<Vec<u8>, Error> {
    if file_id.len() > 255 || agent_id.len() > 255 {
        return Err(Error::InvalidFormat);
    }
    let mut c = Vec::with_capacity(32 + 2 + file_id.len() + agent_id.len());
    c.extend_from_slice(&file::header_hash(sealed)?);
    c.push(file_id.len() as u8);
    c.extend_from_slice(file_id.as_bytes());
    c.push(agent_id.len() as u8);
    c.extend_from_slice(agent_id.as_bytes());
    Ok(c)
}

fn aead_key(ss: &xwing::SharedSecret) -> Result<Zeroizing<[u8; 32]>, Error> {
    let mut k = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(None, ss.as_bytes())
        .expand(INFO, k.as_mut())
        .map_err(|_| Error::InvalidKey)?;
    Ok(k)
}

/// User side: seal a file key to the agent's X-Wing public key.
pub fn wrap_file_key(
    file_key: &[u8; 32],
    agent_kem_pk: &[u8; xwing::PUBLIC_KEY_LEN],
    context: &[u8],
) -> Result<Vec<u8>, Error> {
    let (ss, kem_ct) = xwing::encapsulate(agent_kem_pk)?;
    let mut nonce = [0u8; NONCE_LEN];
    crate::random::fill(&mut nonce)?;

    let mut blob = Vec::with_capacity(BLOB_LEN);
    blob.extend_from_slice(&MAGIC);
    blob.push(VERSION);
    blob.extend_from_slice(&kem_ct);
    blob.extend_from_slice(&nonce);
    let aad = [blob.as_slice(), context].concat();
    let key = aead_key(&ss)?;
    let ct = XChaCha20Poly1305::new((&*key).into())
        .encrypt(&XNonce::from(nonce), Payload { msg: file_key, aad: &aad })
        .map_err(|_| Error::InvalidKey)?;
    blob.extend_from_slice(&ct);
    Ok(blob)
}

/// Agent side: recover the file key with the agent's own X-Wing secret key.
pub fn unwrap_file_key(
    blob: &[u8],
    agent_sk: &xwing::SecretKey,
    context: &[u8],
) -> Result<Zeroizing<[u8; 32]>, Error> {
    if blob.len() != BLOB_LEN || blob[0..4] != MAGIC || blob[4] != VERSION {
        return Err(Error::InvalidFormat);
    }
    let (prefix, ct) = blob.split_at(PREFIX_LEN);
    let kem_ct: &[u8; xwing::CIPHERTEXT_LEN] = prefix[5..5 + xwing::CIPHERTEXT_LEN]
        .try_into()
        .map_err(|_| Error::InvalidFormat)?;
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&prefix[5 + xwing::CIPHERTEXT_LEN..]);
    let ss = xwing::decapsulate(kem_ct, agent_sk);
    let aad = [prefix, context].concat();
    let aead = aead_key(&ss)?;
    let pt = Zeroizing::new(
        XChaCha20Poly1305::new((&*aead).into())
            .decrypt(&XNonce::from(nonce), Payload { msg: ct, aad: &aad })
            .map_err(|_| Error::DecryptionFailed)?,
    );
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&pt);
    Ok(key)
}
