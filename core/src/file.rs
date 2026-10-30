//! SealDrop file format, version 1.
//!
//! ```text
//! sealed file = header (1213 bytes) || body (chunks) || signature (3309 bytes)
//!
//! header:
//!   offset  len   field
//!   0       4     magic "SDRP"
//!   4       1     version (= 1)
//!   5       1     suite (= 1: X-Wing, HKDF-SHA256, XChaCha20-Poly1305, ML-DSA-65)
//!   6       4     chunk size in bytes, big endian (1 ..= 16 MiB)
//!   10      32    sender fingerprint    = SHA3-256(sender ML-DSA public key)
//!   42      32    recipient fingerprint = SHA3-256(recipient X-Wing public key)
//!   74      1120  X-Wing ciphertext
//!   1194    19    random nonce prefix
//!
//! body: the plaintext split into chunks of `chunk size` bytes (the last may be
//! shorter, or empty for an empty file). Each chunk is sealed with
//! XChaCha20-Poly1305 and so grows by a 16 byte tag.
//!   nonce(i) = nonce prefix (19) || i as u32 big endian (4) || last flag (1)
//!   aad      = SHA3-256(header)
//! This is the STREAM construction (Hoang, Reyhanitabar, Rogaway, Vizar 2015):
//! the counter stops chunks being reordered, and the last flag stops an
//! attacker cutting chunks off the end without detection.
//!
//! key schedule:
//!   ss       = X-Wing shared secret
//!   file key = HKDF-SHA256(ikm = ss, salt = none,
//!                          info = "SealDrop v1 file key" || SHA3-256(header))
//!
//! signature: ML-DSA-65 with context "SealDrop v1 file" over
//!   header || SHA3-256(body)
//! The recipient verifies it before doing any decryption.
//! ```

use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use sha2::Sha256;
use sha3::{Digest, Sha3_256};
use zeroize::Zeroizing;

use crate::{
    Error,
    identity::{SecretIdentity, fingerprint},
    sign, xwing,
};

pub const MAGIC: [u8; 4] = *b"SDRP";
pub const VERSION: u8 = 1;
pub const SUITE: u8 = 1;
pub const HEADER_LEN: usize = 4 + 1 + 1 + 4 + 32 + 32 + xwing::CIPHERTEXT_LEN + NONCE_PREFIX_LEN;
pub const TAG_LEN: usize = 16;
pub const DEFAULT_CHUNK_SIZE: u32 = 64 * 1024;
pub const MAX_CHUNK_SIZE: u32 = 16 * 1024 * 1024;
pub const SIGNATURE_CONTEXT: &[u8] = b"SealDrop v1 file";

pub const NONCE_PREFIX_LEN: usize = 19;
const FILE_KEY_INFO: &[u8] = b"SealDrop v1 file key";

/// The public, unencrypted facts a header tells you.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderInfo {
    pub chunk_size: u32,
    pub sender_fingerprint: [u8; 32],
    pub recipient_fingerprint: [u8; 32],
}

/// Encrypt and sign `plaintext` for `recipient_kem_pk`, using 64 KiB chunks.
pub fn seal(
    plaintext: &[u8],
    recipient_kem_pk: &[u8; xwing::PUBLIC_KEY_LEN],
    sender: &SecretIdentity,
) -> Result<Vec<u8>, Error> {
    seal_with_chunk_size(plaintext, recipient_kem_pk, sender, DEFAULT_CHUNK_SIZE)
}

pub fn seal_with_chunk_size(
    plaintext: &[u8],
    recipient_kem_pk: &[u8; xwing::PUBLIC_KEY_LEN],
    sender: &SecretIdentity,
    chunk_size: u32,
) -> Result<Vec<u8>, Error> {
    if chunk_size == 0 || chunk_size > MAX_CHUNK_SIZE {
        return Err(Error::InvalidFormat);
    }
    let (ss, kem_ct) = xwing::encapsulate(recipient_kem_pk)?;
    let mut nonce_prefix = [0u8; NONCE_PREFIX_LEN];
    crate::random::fill(&mut nonce_prefix)?;

    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(&MAGIC);
    header.push(VERSION);
    header.push(SUITE);
    header.extend_from_slice(&chunk_size.to_be_bytes());
    header.extend_from_slice(&fingerprint(&sender.sig.verifying_key()));
    header.extend_from_slice(&fingerprint(recipient_kem_pk));
    header.extend_from_slice(&kem_ct);
    header.extend_from_slice(&nonce_prefix);
    debug_assert_eq!(header.len(), HEADER_LEN);

    let header_hash = sha3(&header);
    let key = derive_file_key(ss.as_bytes(), &header_hash)?;
    let body = encrypt_body(&key, &nonce_prefix, &header_hash, plaintext, chunk_size)?;

    let sig = sign::sign(&sender.sig, &signed_message(&header, &body), SIGNATURE_CONTEXT)?;

    let mut out = header;
    out.reserve(body.len() + sign::SIGNATURE_LEN);
    out.extend_from_slice(&body);
    out.extend_from_slice(&sig);
    Ok(out)
}

/// Read the header without verifying or decrypting anything. Use it to learn
/// which sender public key to fetch; then call [`open`].
pub fn peek_header(sealed: &[u8]) -> Result<HeaderInfo, Error> {
    let (header, _, _) = split(sealed)?;
    parse_header(header)
}

/// Verify the sender's signature, then decrypt. Fails closed: no plaintext is
/// returned unless the signature and every chunk's tag are valid.
pub fn open(sealed: &[u8], recipient: &SecretIdentity, sender_sig_vk: &[u8]) -> Result<Vec<u8>, Error> {
    let (header, body, sig) = split(sealed)?;
    let info = parse_header(header)?;

    // 1. Signature first: is this really from the claimed sender, unmodified?
    if info.sender_fingerprint != fingerprint(sender_sig_vk) {
        return Err(Error::BadSignature);
    }
    sign::verify(sender_sig_vk, &signed_message(header, body), SIGNATURE_CONTEXT, sig)?;

    // 2. Only now touch secret keys.
    let kem_ct: &[u8; xwing::CIPHERTEXT_LEN] =
        header[74..74 + xwing::CIPHERTEXT_LEN].try_into().map_err(|_| Error::InvalidFormat)?;
    let nonce_prefix: &[u8; NONCE_PREFIX_LEN] =
        header[74 + xwing::CIPHERTEXT_LEN..].try_into().map_err(|_| Error::InvalidFormat)?;
    let ss = xwing::decapsulate(kem_ct, &recipient.kem);
    let header_hash = sha3(header);
    let key = derive_file_key(ss.as_bytes(), &header_hash)?;
    decrypt_body(&key, nonce_prefix, &header_hash, body, info.chunk_size)
}

/// (header, body, signature)
type Parts<'a> = (&'a [u8], &'a [u8], &'a [u8]);

fn split(sealed: &[u8]) -> Result<Parts<'_>, Error> {
    // Smallest valid file: header, one empty final chunk (just a tag), signature.
    if sealed.len() < HEADER_LEN + TAG_LEN + sign::SIGNATURE_LEN {
        return Err(Error::InvalidFormat);
    }
    let (header, rest) = sealed.split_at(HEADER_LEN);
    let (body, sig) = rest.split_at(rest.len() - sign::SIGNATURE_LEN);
    Ok((header, body, sig))
}

fn parse_header(header: &[u8]) -> Result<HeaderInfo, Error> {
    if header.len() != HEADER_LEN || header[0..4] != MAGIC {
        return Err(Error::InvalidFormat);
    }
    if header[4] != VERSION || header[5] != SUITE {
        return Err(Error::InvalidFormat);
    }
    let chunk_size = u32::from_be_bytes([header[6], header[7], header[8], header[9]]);
    if chunk_size == 0 || chunk_size > MAX_CHUNK_SIZE {
        return Err(Error::InvalidFormat);
    }
    let mut sender_fingerprint = [0u8; 32];
    let mut recipient_fingerprint = [0u8; 32];
    sender_fingerprint.copy_from_slice(&header[10..42]);
    recipient_fingerprint.copy_from_slice(&header[42..74]);
    Ok(HeaderInfo { chunk_size, sender_fingerprint, recipient_fingerprint })
}

fn signed_message(header: &[u8], body: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(header.len() + 32);
    m.extend_from_slice(header);
    m.extend_from_slice(&sha3(body));
    m
}

fn sha3(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha3_256::digest(data));
    out
}

fn derive_file_key(ss: &[u8; 32], header_hash: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, Error> {
    let mut info = Vec::with_capacity(FILE_KEY_INFO.len() + 32);
    info.extend_from_slice(FILE_KEY_INFO);
    info.extend_from_slice(header_hash);
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(None, ss)
        .expand(&info, key.as_mut())
        .map_err(|_| Error::InvalidKey)?;
    Ok(key)
}

fn chunk_nonce(prefix: &[u8; NONCE_PREFIX_LEN], index: u32, last: bool) -> XNonce {
    let mut n = [0u8; 24];
    n[..NONCE_PREFIX_LEN].copy_from_slice(prefix);
    n[NONCE_PREFIX_LEN..23].copy_from_slice(&index.to_be_bytes());
    n[23] = u8::from(last);
    XNonce::from(n)
}

/// Low level: STREAM-encrypt `plaintext` in chunks. Public so benchmarks can
/// compare against a classic (X25519 only) key exchange using the same body.
pub fn encrypt_body(
    key: &[u8; 32],
    nonce_prefix: &[u8; NONCE_PREFIX_LEN],
    aad: &[u8],
    plaintext: &[u8],
    chunk_size: u32,
) -> Result<Vec<u8>, Error> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let cs = chunk_size as usize;
    // An empty file is a single empty final chunk.
    let n_chunks = plaintext.len().div_ceil(cs).max(1);
    if n_chunks > u32::MAX as usize {
        return Err(Error::InvalidFormat);
    }
    let mut out = Vec::with_capacity(plaintext.len() + n_chunks * TAG_LEN);
    for i in 0..n_chunks {
        let start = i * cs;
        let end = (start + cs).min(plaintext.len());
        let last = i + 1 == n_chunks;
        let nonce = chunk_nonce(nonce_prefix, i as u32, last);
        let ct = cipher
            .encrypt(&nonce, Payload { msg: &plaintext[start..end], aad })
            .map_err(|_| Error::InvalidFormat)?;
        out.extend_from_slice(&ct);
    }
    Ok(out)
}

/// Low level: inverse of [`encrypt_body`].
pub fn decrypt_body(
    key: &[u8; 32],
    nonce_prefix: &[u8; NONCE_PREFIX_LEN],
    aad: &[u8],
    body: &[u8],
    chunk_size: u32,
) -> Result<Vec<u8>, Error> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let sealed_chunk = chunk_size as usize + TAG_LEN;
    let n_chunks = body.len().div_ceil(sealed_chunk);
    if n_chunks == 0 || n_chunks > u32::MAX as usize {
        return Err(Error::DecryptionFailed);
    }
    let mut out = Vec::with_capacity(body.len());
    for (i, chunk) in body.chunks(sealed_chunk).enumerate() {
        let last = i + 1 == n_chunks;
        let nonce = chunk_nonce(nonce_prefix, i as u32, last);
        let pt = cipher
            .decrypt(&nonce, Payload { msg: chunk, aad })
            .map_err(|_| Error::DecryptionFailed)?;
        out.extend_from_slice(&pt);
    }
    Ok(out)
}
