//! ML-DSA-65 signatures (FIPS 204), using the RustCrypto `ml-dsa` crate.
//!
//! We store the 32 byte seed `xi` as the private key (FIPS 204 Algorithm 6,
//! `ML-DSA.KeyGen_internal(xi)`) and expand it when needed. Signing is the
//! default "hedged" mode of FIPS 204 Algorithm 2: fresh randomness is mixed
//! in, so a bad RNG cannot leak the key the way it can with ECDSA.

use ml_dsa::{EncodedVerifyingKey, MlDsa65, Signature, SigningKey, VerifyingKey};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::Error;

pub const SEED_LEN: usize = 32;
/// FIPS 204 Table 2: ML-DSA-65 public key is 1952 bytes.
pub const VERIFYING_KEY_LEN: usize = 1952;
/// FIPS 204 Table 2: ML-DSA-65 signature is 3309 bytes.
pub const SIGNATURE_LEN: usize = 3309;

/// The 32 byte ML-DSA-65 key generation seed. Wiped on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SigningSeed([u8; SEED_LEN]);

impl SigningSeed {
    pub fn from_bytes(bytes: [u8; SEED_LEN]) -> Self {
        Self(bytes)
    }
    pub fn as_bytes(&self) -> &[u8; SEED_LEN] {
        &self.0
    }

    fn expand(&self) -> SigningKey<MlDsa65> {
        SigningKey::<MlDsa65>::from_seed(&self.0.into())
    }

    /// The matching 1952 byte public verifying key.
    pub fn verifying_key(&self) -> [u8; VERIFYING_KEY_LEN] {
        let vk = self.expand().expanded_key().verifying_key().encode();
        let mut out = [0u8; VERIFYING_KEY_LEN];
        out.copy_from_slice(vk.as_slice());
        out
    }
}

/// Generate a new signing seed from OS randomness.
pub fn generate() -> Result<SigningSeed, Error> {
    let mut seed = [0u8; SEED_LEN];
    crate::random::fill(&mut seed)?;
    Ok(SigningSeed(seed))
}

/// FIPS 204 Algorithm 2 `ML-DSA.Sign(sk, M, ctx)` (hedged).
/// `ctx` is the FIPS 204 context string (at most 255 bytes), used for
/// domain separation so a SealDrop signature can't be replayed elsewhere.
pub fn sign(seed: &SigningSeed, msg: &[u8], ctx: &[u8]) -> Result<[u8; SIGNATURE_LEN], Error> {
    let sk = seed.expand();
    let sig = sk
        .expanded_key()
        .sign_randomized(msg, ctx, &mut getrandom::SysRng)
        .map_err(|_| Error::Randomness)?;
    let mut out = [0u8; SIGNATURE_LEN];
    out.copy_from_slice(sig.encode().as_slice());
    Ok(out)
}

/// FIPS 204 Algorithm 3 `ML-DSA.Verify(pk, M, sigma, ctx)`.
/// Takes byte slices so that wrong-length input is an error, not a panic.
pub fn verify(vk: &[u8], msg: &[u8], ctx: &[u8], sig: &[u8]) -> Result<(), Error> {
    let vk_enc = EncodedVerifyingKey::<MlDsa65>::try_from(vk).map_err(|_| Error::BadSignature)?;
    let vk = VerifyingKey::<MlDsa65>::decode(&vk_enc);
    let sig = Signature::<MlDsa65>::try_from(sig).map_err(|_| Error::BadSignature)?;
    if vk.verify_with_context(msg, ctx, &sig) {
        Ok(())
    } else {
        Err(Error::BadSignature)
    }
}
