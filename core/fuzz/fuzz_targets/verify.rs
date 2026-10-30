//! Arbitrary signatures, messages and public keys into ML-DSA-65 verify.
#![no_main]

use libfuzzer_sys::fuzz_target;
use sealdrop_core::sign;
use std::sync::OnceLock;

fn vk() -> &'static [u8; sign::VERIFYING_KEY_LEN] {
    static VK: OnceLock<[u8; sign::VERIFYING_KEY_LEN]> = OnceLock::new();
    VK.get_or_init(|| sign::SigningSeed::from_bytes([8; 32]).verifying_key())
}

/// Copy `data` into a fixed-length buffer (zero padded), so the fuzzer reaches
/// the decoding and verification logic instead of the length check.
fn padded<const N: usize>(data: &[u8]) -> [u8; N] {
    let mut out = [0u8; N];
    let n = data.len().min(N);
    out[..n].copy_from_slice(&data[..n]);
    out
}

fuzz_target!(|data: &[u8]| {
    let msg_len = data.first().map(|b| *b as usize).unwrap_or(0).min(data.len());
    let (msg, rest) = data.split_at(msg_len);
    // Raw input: exercises the length checks.
    let _ = sign::verify(vk(), msg, b"SealDrop v1 file", rest);
    // Exact-length signature: exercises sigDecode, hint unpacking, norm checks, Verify.
    let sig: [u8; sign::SIGNATURE_LEN] = padded(rest);
    let _ = sign::verify(vk(), msg, b"SealDrop v1 file", &sig);
    // Arbitrary public key with an exact-length signature.
    let pk: [u8; sign::VERIFYING_KEY_LEN] = padded(rest);
    let _ = sign::verify(&pk, msg, b"", &sig);
});
