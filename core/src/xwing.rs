//! X-Wing hybrid KEM (X25519 + ML-KEM-768).
//!
//! Specification: draft-connolly-cfrg-xwing-kem-11 (23 September 2026),
//! <https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/11/>.
//!
//! This file only *combines* existing primitives exactly as the draft says:
//! ML-KEM-768 comes from the RustCrypto `ml-kem` crate, X25519 from
//! `x25519-dalek`, SHAKE256 from `shake` and SHA3-256 from `sha3`.
//! Each function quotes the pseudocode section it implements.

use ml_kem::{
    Decapsulate, DecapsulationKey768, EncapsulationKey768, KeyExport, array::Array,
};
use sha3::{Digest, Sha3_256};
use shake::{ExtendableOutput, Shake256, Update, XofReader};
use subtle::{Choice, ConstantTimeEq};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::Error;

/// Section 5.1: "Decapsulation key (private): 32 bytes".
pub const SECRET_KEY_LEN: usize = 32;
/// Section 5.1: "Encapsulation key (public): 1216 bytes".
pub const PUBLIC_KEY_LEN: usize = 1216;
/// Section 5.1: "Ciphertext: 1120 bytes".
pub const CIPHERTEXT_LEN: usize = 1120;
/// Section 5.1: "Shared secret: 32 bytes".
pub const SHARED_SECRET_LEN: usize = 32;

const MLKEM_PK_LEN: usize = 1184;
const MLKEM_CT_LEN: usize = 1088;

/// Section 5.3: "In hexadecimal, XWingLabel is given by 5c2e2f2f5e5c."
const XWING_LABEL: [u8; 6] = [0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c];

/// Section 3: "X25519_BASE: the 32 byte string representing the standard base
/// point of Curve25519 ... 0900...00".
const X25519_BASE: [u8; 32] = {
    let mut b = [0u8; 32];
    b[0] = 9;
    b
};

/// The 32 byte X-Wing decapsulation (private) key. Wiped from memory on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey([u8; SECRET_KEY_LEN]);

impl SecretKey {
    pub fn from_bytes(bytes: [u8; SECRET_KEY_LEN]) -> Self {
        Self(bytes)
    }
    pub fn as_bytes(&self) -> &[u8; SECRET_KEY_LEN] {
        &self.0
    }
}

/// The 32 byte shared secret. Wiped on drop, compared in constant time.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret([u8; SHARED_SECRET_LEN]);

impl SharedSecret {
    pub fn as_bytes(&self) -> &[u8; SHARED_SECRET_LEN] {
        &self.0
    }
}

impl ConstantTimeEq for SharedSecret {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

/// The four values that `expandDecapsulationKey` returns.
struct Expanded {
    sk_m: DecapsulationKey768,
    sk_x: StaticSecret,
    pk_m: [u8; MLKEM_PK_LEN],
    pk_x: [u8; 32],
}

/// Section 5.2:
/// ```text
/// def expandDecapsulationKey(sk):
///   expanded = SHAKE256(sk, 96*8) # expand sk to 96 bytes using SHAKE256
///   (pk_M, sk_M) = ML-KEM-768.KeyGen_internal(expanded[0:32], expanded[32:64])
///   sk_X = expanded[64:96]
///   pk_X = X25519(sk_X, X25519_BASE)
///   return (sk_M, sk_X, pk_M, pk_X)
/// ```
fn expand_decapsulation_key(sk: &SecretKey) -> Expanded {
    let mut expanded = Zeroizing::new([0u8; 96]);
    let mut xof = Shake256::default();
    xof.update(&sk.0);
    xof.finalize_xof().read(expanded.as_mut());

    // `from_seed(d || z)` is ML-KEM-768.KeyGen_internal(d, z) (FIPS 203 Alg. 16),
    // with d = expanded[0:32] and z = expanded[32:64].
    let mut seed_m = Array::default();
    seed_m.copy_from_slice(&expanded[0..64]);
    let sk_m = DecapsulationKey768::from_seed(seed_m);
    seed_m.zeroize();

    let mut sk_x_bytes = Zeroizing::new([0u8; 32]);
    sk_x_bytes.copy_from_slice(&expanded[64..96]);
    let sk_x = StaticSecret::from(*sk_x_bytes);
    // X25519(sk_X, X25519_BASE): scalar multiplication by the base point.
    let pk_x = sk_x.diffie_hellman(&PublicKey::from(X25519_BASE)).to_bytes();

    let mut pk_m = [0u8; MLKEM_PK_LEN];
    pk_m.copy_from_slice(sk_m.encapsulation_key().to_bytes().as_slice());

    Expanded { sk_m, sk_x, pk_m, pk_x }
}

/// Section 5.3:
/// ```text
/// def Combiner(ss_M, ss_X, ct_X, pk_X):
///   return SHA3-256(concat(ss_M, ss_X, ct_X, pk_X, XWingLabel))
/// ```
fn combiner(ss_m: &[u8], ss_x: &[u8], ct_x: &[u8], pk_x: &[u8]) -> SharedSecret {
    let mut h = Sha3_256::new();
    Digest::update(&mut h, ss_m);
    Digest::update(&mut h, ss_x);
    Digest::update(&mut h, ct_x);
    Digest::update(&mut h, pk_x);
    Digest::update(&mut h, XWING_LABEL);
    let mut out = [0u8; SHARED_SECRET_LEN];
    out.copy_from_slice(&h.finalize());
    SharedSecret(out)
}

/// Section 5.2.1:
/// ```text
/// def GenerateKeyPairDerand(sk):
///   sk_M, sk_X, pk_M, pk_X = expandDecapsulationKey(sk)
///   return sk, concat(pk_M, pk_X)
/// ```
pub fn generate_keypair_derand(sk: SecretKey) -> (SecretKey, [u8; PUBLIC_KEY_LEN]) {
    let e = expand_decapsulation_key(&sk);
    let mut pk = [0u8; PUBLIC_KEY_LEN];
    pk[..MLKEM_PK_LEN].copy_from_slice(&e.pk_m);
    pk[MLKEM_PK_LEN..].copy_from_slice(&e.pk_x);
    (sk, pk)
}

/// Section 5.2:
/// ```text
/// def GenerateKeyPair():
///   sk = random(32)
///   (sk_M, sk_X, pk_M, pk_X) = expandDecapsulationKey(sk)
///   return sk, concat(pk_M, pk_X)
/// ```
pub fn generate_keypair() -> Result<(SecretKey, [u8; PUBLIC_KEY_LEN]), Error> {
    let mut sk = [0u8; SECRET_KEY_LEN];
    crate::random::fill(&mut sk)?;
    Ok(generate_keypair_derand(SecretKey(sk)))
}

/// Section 5.4.1:
/// ```text
/// def EncapsulateDerand(pk, eseed):
///   pk_M = pk[0:1184]
///   pk_X = pk[1184:1216]
///   ek_X = eseed[32:64]
///   ct_X = X25519(ek_X, X25519_BASE)
///   ss_X = X25519(ek_X, pk_X)
///   (ss_M, ct_M) = ML-KEM-768.EncapsDerand(pk_M, eseed[0:32])
///   ss = Combiner(ss_M, ss_X, ct_X, pk_X)
///   ct = concat(ct_M, ct_X)
///   return (ss, ct)
/// ```
///
/// Only for known answer tests: reusing `eseed` is catastrophic. Normal code
/// must call [`encapsulate`], which feeds this function fresh OS randomness
/// ("Encapsulate(pk) can be implemented as EncapsulateDerand(pk,random(64))").
#[cfg(any(test, feature = "hazmat"))]
pub fn encapsulate_derand(
    pk: &[u8; PUBLIC_KEY_LEN],
    eseed: &[u8; 64],
) -> Result<(SharedSecret, [u8; CIPHERTEXT_LEN]), Error> {
    encapsulate_inner(pk, eseed)
}

fn encapsulate_inner(
    pk: &[u8; PUBLIC_KEY_LEN],
    eseed: &[u8; 64],
) -> Result<(SharedSecret, [u8; CIPHERTEXT_LEN]), Error> {
    let pk_m = &pk[0..MLKEM_PK_LEN];
    let pk_x: [u8; 32] = pk[MLKEM_PK_LEN..PUBLIC_KEY_LEN]
        .try_into()
        .map_err(|_| Error::InvalidKey)?;

    let mut ek_x_bytes = Zeroizing::new([0u8; 32]);
    ek_x_bytes.copy_from_slice(&eseed[32..64]);
    let ek_x = StaticSecret::from(*ek_x_bytes);
    let ct_x = ek_x.diffie_hellman(&PublicKey::from(X25519_BASE)).to_bytes();
    let ss_x = ek_x.diffie_hellman(&PublicKey::from(pk_x));

    // Section 4: "ML-KEM-768.Encaps_internal(pk_M) MUST perform the
    // encapsulation key check of [MLKEM] §7.2 and raise an error if it fails."
    // `EncapsulationKey768::new` performs exactly that check.
    let pk_m_arr = Array::try_from(pk_m).map_err(|_| Error::InvalidKey)?;
    let ek_m = EncapsulationKey768::new(&pk_m_arr).map_err(|_| Error::InvalidKey)?;
    let mut m = Array::default();
    m.copy_from_slice(&eseed[0..32]);
    let (ct_m, mut ss_m) = ek_m.encapsulate_deterministic(&m);
    m.zeroize();

    let ss = combiner(ss_m.as_slice(), ss_x.as_bytes(), &ct_x, &pk_x);
    ss_m.zeroize();

    let mut ct = [0u8; CIPHERTEXT_LEN];
    ct[..MLKEM_CT_LEN].copy_from_slice(ct_m.as_slice());
    ct[MLKEM_CT_LEN..].copy_from_slice(&ct_x);
    Ok((ss, ct))
}

/// Section 5.4 `Encapsulate(pk)`, implemented as the draft allows:
/// "Encapsulate(pk) can be implemented as EncapsulateDerand(pk,random(64))."
pub fn encapsulate(
    pk: &[u8; PUBLIC_KEY_LEN],
) -> Result<(SharedSecret, [u8; CIPHERTEXT_LEN]), Error> {
    let mut eseed = Zeroizing::new([0u8; 64]);
    crate::random::fill(eseed.as_mut())?;
    encapsulate_inner(pk, &eseed)
}

/// Section 5.5:
/// ```text
/// def Decapsulate(ct, sk):
///   (sk_M, sk_X, pk_M, pk_X) = expandDecapsulationKey(sk)
///   ct_M = ct[0:1088]
///   ct_X = ct[1088:1120]
///   ss_M = ML-KEM-768.Decapsulate(ct_M, sk_M)
///   ss_X = X25519(sk_X, ct_X)
///   return Combiner(ss_M, ss_X, ct_X, pk_X)
/// ```
///
/// ML-KEM uses implicit rejection: a tampered ciphertext does not raise an
/// error, it yields an unrelated pseudorandom secret. The later AEAD step is
/// what turns that into a decryption failure.
pub fn decapsulate(ct: &[u8; CIPHERTEXT_LEN], sk: &SecretKey) -> SharedSecret {
    let e = expand_decapsulation_key(sk);
    let mut ct_m = Array::default();
    ct_m.copy_from_slice(&ct[0..MLKEM_CT_LEN]);
    let mut ct_x = [0u8; 32];
    ct_x.copy_from_slice(&ct[MLKEM_CT_LEN..CIPHERTEXT_LEN]);

    let mut ss_m = e.sk_m.decapsulate(&ct_m);
    let ss_x = e.sk_x.diffie_hellman(&PublicKey::from(ct_x));
    let ss = combiner(ss_m.as_slice(), ss_x.as_bytes(), &ct_x, &e.pk_x);
    ss_m.zeroize();
    ss
}
