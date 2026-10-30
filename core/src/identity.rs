//! A SealDrop user owns two keypairs:
//! - an X-Wing keypair, so others can encrypt files *to* them, and
//! - an ML-DSA-65 keypair, so they can sign files they *send*.
//!
//! Both private keys are 32 byte seeds, so the whole secret identity is
//! 64 bytes. That is what gets wrapped (encrypted) by [`crate::keywrap`].

use sha3::{Digest, Sha3_256};
use zeroize::Zeroizing;

use crate::{Error, sign, xwing};

pub const SECRET_LEN: usize = xwing::SECRET_KEY_LEN + sign::SEED_LEN;

pub struct SecretIdentity {
    pub kem: xwing::SecretKey,
    pub sig: sign::SigningSeed,
}

#[derive(Clone)]
pub struct PublicIdentity {
    pub kem_pk: [u8; xwing::PUBLIC_KEY_LEN],
    pub sig_vk: [u8; sign::VERIFYING_KEY_LEN],
}

impl SecretIdentity {
    pub fn generate() -> Result<Self, Error> {
        let (kem, _) = xwing::generate_keypair()?;
        let sig = sign::generate()?;
        Ok(Self { kem, sig })
    }

    pub fn public(&self) -> PublicIdentity {
        let (_, kem_pk) = xwing::generate_keypair_derand(self.kem.clone());
        PublicIdentity { kem_pk, sig_vk: self.sig.verifying_key() }
    }

    /// 64 bytes: X-Wing seed || ML-DSA seed. Wiped when the returned value drops.
    pub fn to_bytes(&self) -> Zeroizing<[u8; SECRET_LEN]> {
        let mut out = Zeroizing::new([0u8; SECRET_LEN]);
        out[..32].copy_from_slice(self.kem.as_bytes());
        out[32..].copy_from_slice(self.sig.as_bytes());
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != SECRET_LEN {
            return Err(Error::InvalidKey);
        }
        let mut kem = Zeroizing::new([0u8; 32]);
        let mut sig = Zeroizing::new([0u8; 32]);
        kem.copy_from_slice(&bytes[..32]);
        sig.copy_from_slice(&bytes[32..]);
        Ok(Self {
            kem: xwing::SecretKey::from_bytes(*kem),
            sig: sign::SigningSeed::from_bytes(*sig),
        })
    }
}

/// SHA3-256 of a public key. Used in file headers to say which keys were used,
/// without having to embed the (large) keys themselves.
pub fn fingerprint(public_key: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha3_256::digest(public_key));
    out
}
