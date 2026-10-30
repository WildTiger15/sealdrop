//! Arbitrary ciphertexts into decapsulate, arbitrary public keys into
//! encapsulate (which must reject invalid ML-KEM keys, not panic).
#![no_main]

use libfuzzer_sys::fuzz_target;
use sealdrop_core::xwing;

fn padded<const N: usize>(data: &[u8]) -> [u8; N] {
    let mut out = [0u8; N];
    let n = data.len().min(N);
    out[..n].copy_from_slice(&data[..n]);
    out
}

fuzz_target!(|data: &[u8]| {
    let ct: [u8; xwing::CIPHERTEXT_LEN] = padded(data);
    let sk = xwing::SecretKey::from_bytes(padded(data.get(xwing::CIPHERTEXT_LEN..).unwrap_or(&[])));
    let _ = xwing::decapsulate(&ct, &sk);

    let pk: [u8; xwing::PUBLIC_KEY_LEN] = padded(data);
    let _ = xwing::encapsulate_derand(&pk, &[9; 64]);
});
