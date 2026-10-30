//! Wrapping (encrypting) a user's 64 byte secret identity so the encrypted
//! blob can be stored on the server, which cannot open it.
//!
//! The wrapping key comes from one of two places:
//! 1. Passkey PRF (preferred): the WebAuthn PRF extension returns 32 secret
//!    bytes that only the authenticator can produce. We pass them through
//!    HKDF-SHA256 to get the wrapping key.
//! 2. Passphrase (fallback, WEAKER): Argon2id over a user passphrase. Its
//!    strength is only as good as the passphrase.
//!
//! ```text
//! blob = "SDKW" || version (1) || kdf (1) || salt (16) || nonce (24) || ciphertext (64 + 16)
//! aad  = the first 46 bytes of the blob || caller context (e.g. the username)
//! ```
//! Putting the username in the AAD means the server can't swap one user's
//! wrapped keys into another user's account without the unwrap failing.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{
    Error,
    identity::{SECRET_LEN, SecretIdentity},
};

pub const MAGIC: [u8; 4] = *b"SDKW";
pub const VERSION: u8 = 1;
pub const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const PREFIX_LEN: usize = 4 + 1 + 1 + SALT_LEN + NONCE_LEN;
pub const BLOB_LEN: usize = PREFIX_LEN + SECRET_LEN + 16;

const PRF_INFO: &[u8] = b"SealDrop v1 PRF wrapping key";

/// Argon2id cost: 64 MiB memory, 3 passes, 1 lane (OWASP's recommended minimum
/// is 19 MiB / 2 passes; we go higher because this runs once per sign in).
const ARGON2_M_KIB: u32 = 64 * 1024;
const ARGON2_T: u32 = 3;
const ARGON2_P: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum KdfKind {
    Prf = 1,
    Passphrase = 2,
}

impl KdfKind {
    fn from_byte(b: u8) -> Result<Self, Error> {
        match b {
            1 => Ok(KdfKind::Prf),
            2 => Ok(KdfKind::Passphrase),
            _ => Err(Error::InvalidFormat),
        }
    }
}

/// HKDF-SHA256 over the passkey PRF output.
pub fn wrapping_key_from_prf(prf_output: &[u8]) -> Result<Zeroizing<[u8; 32]>, Error> {
    if prf_output.len() < 32 {
        return Err(Error::InvalidKey);
    }
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(None, prf_output)
        .expand(PRF_INFO, key.as_mut())
        .map_err(|_| Error::InvalidKey)?;
    Ok(key)
}

/// Argon2id over a passphrase. Weaker than PRF: an attacker who steals the
/// blob can guess passphrases offline (slowly, because of Argon2id).
pub fn wrapping_key_from_passphrase(
    passphrase: &[u8],
    salt: &[u8; SALT_LEN],
) -> Result<Zeroizing<[u8; 32]>, Error> {
    let params = Params::new(ARGON2_M_KIB, ARGON2_T, ARGON2_P, Some(32)).map_err(|_| Error::InvalidKey)?;
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(passphrase, salt, key.as_mut())
        .map_err(|_| Error::InvalidKey)?;
    Ok(key)
}

/// A fresh random salt for [`wrapping_key_from_passphrase`].
pub fn new_salt() -> Result<[u8; SALT_LEN], Error> {
    let mut s = [0u8; SALT_LEN];
    crate::random::fill(&mut s)?;
    Ok(s)
}

/// Encrypt `identity` under `wrapping_key`. `salt` is stored in the blob so a
/// passphrase user can re-derive the key later (all zeros for PRF).
pub fn wrap(
    wrapping_key: &[u8; 32],
    kdf: KdfKind,
    salt: &[u8; SALT_LEN],
    identity: &SecretIdentity,
    context: &[u8],
) -> Result<Vec<u8>, Error> {
    let mut nonce = [0u8; NONCE_LEN];
    crate::random::fill(&mut nonce)?;

    let mut blob = Vec::with_capacity(BLOB_LEN);
    blob.extend_from_slice(&MAGIC);
    blob.push(VERSION);
    blob.push(kdf as u8);
    blob.extend_from_slice(salt);
    blob.extend_from_slice(&nonce);

    let aad = [blob.as_slice(), context].concat();
    let secret = identity.to_bytes();
    let ct = XChaCha20Poly1305::new(wrapping_key.into())
        .encrypt(&XNonce::from(nonce), Payload { msg: secret.as_slice(), aad: &aad })
        .map_err(|_| Error::InvalidKey)?;
    blob.extend_from_slice(&ct);
    Ok(blob)
}

/// Read which KDF and salt a blob needs, before deriving the key.
pub fn blob_kdf(blob: &[u8]) -> Result<(KdfKind, [u8; SALT_LEN]), Error> {
    if blob.len() != BLOB_LEN || blob[0..4] != MAGIC || blob[4] != VERSION {
        return Err(Error::InvalidFormat);
    }
    let kdf = KdfKind::from_byte(blob[5])?;
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&blob[6..6 + SALT_LEN]);
    Ok((kdf, salt))
}

pub fn unwrap(wrapping_key: &[u8; 32], blob: &[u8], context: &[u8]) -> Result<SecretIdentity, Error> {
    blob_kdf(blob)?;
    let (prefix, ct) = blob.split_at(PREFIX_LEN);
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&prefix[6 + SALT_LEN..]);
    let aad = [prefix, context].concat();
    let secret = Zeroizing::new(
        XChaCha20Poly1305::new(wrapping_key.into())
            .decrypt(&XNonce::from(nonce), Payload { msg: ct, aad: &aad })
            .map_err(|_| Error::DecryptionFailed)?,
    );
    SecretIdentity::from_bytes(&secret)
}
