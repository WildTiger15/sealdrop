//! A tour of the sealdrop-core API. Run with:
//!   cargo run -p sealdrop-core --example quickstart --release

use sealdrop_core::{
    Error, file,
    identity::{SecretIdentity, fingerprint},
    keywrap::{self, KdfKind},
    sign, xwing,
};
use subtle::ConstantTimeEq; // secrets are compared in constant time, even in examples

fn short(b: &[u8]) -> String {
    b[..8].iter().map(|x| format!("{x:02x}")).collect()
}

fn main() -> Result<(), Error> {
    // 1. The hybrid KEM on its own: both sides end up with the same 32 byte secret.
    let (bob_sk, bob_pk) = xwing::generate_keypair()?;
    let (ss_sender, ct) = xwing::encapsulate(&bob_pk)?;
    let ss_receiver = xwing::decapsulate(&ct, &bob_sk);
    println!("X-Wing: public key {} B, ciphertext {} B, secrets equal: {}",
        bob_pk.len(), ct.len(), bool::from(ss_sender.ct_eq(&ss_receiver)));

    // 2. Signatures on their own.
    let seed = sign::generate()?;
    let sig = sign::sign(&seed, b"hello", b"example")?;
    let vk = seed.verifying_key();
    println!("ML-DSA-65: verifying key {} B, signature {} B, valid: {}, wrong message rejected: {}",
        vk.len(), sig.len(),
        sign::verify(&vk, b"hello", b"example", &sig).is_ok(),
        sign::verify(&vk, b"hellO", b"example", &sig).is_err());

    // 3. A whole file from alice to bob: encrypt + sign, then verify + decrypt.
    let alice = SecretIdentity::generate()?;
    let bob = SecretIdentity::generate()?;
    let plaintext = b"Meet at the usual place at 10.".repeat(100);
    let sealed = file::seal(&plaintext, &bob.public().kem_pk, &alice)?;
    let header = file::peek_header(&sealed)?;
    println!("sealed {} B -> {} B (overhead {} B), sender fingerprint {}..",
        plaintext.len(), sealed.len(), sealed.len() - plaintext.len(), short(&header.sender_fingerprint));
    assert_eq!(header.sender_fingerprint, fingerprint(&alice.public().sig_vk));
    let opened = file::open(&sealed, &bob, &alice.public().sig_vk)?;
    println!("bob opened it: plaintext matches: {}", opened == plaintext);

    // 4. What goes wrong is rejected, with coarse errors.
    let eve = SecretIdentity::generate()?;
    let mut tampered = sealed.clone();
    tampered[2000] ^= 1;
    println!("eve opens it:            {:?}", file::open(&sealed, &eve, &alice.public().sig_vk).err());
    println!("one bit flipped:         {:?}", file::open(&tampered, &bob, &alice.public().sig_vk).err());
    println!("checked against eve key: {:?}", file::open(&sealed, &bob, &eve.public().sig_vk).err());

    // 5. Key wrapping: what the server stores instead of your private keys.
    let prf_output = [7u8; 32]; // in the app this comes from the passkey (WebAuthn PRF)
    let wrapping_key = keywrap::wrapping_key_from_prf(&prf_output)?;
    let blob = keywrap::wrap(&wrapping_key, KdfKind::Prf, &[0; 16], &bob, b"bob")?;
    let back = keywrap::unwrap(&wrapping_key, &blob, b"bob")?;
    println!("wrapped identity: {} B blob, unwraps to the same keys: {}, under another username: {:?}",
        blob.len(), back.public().kem_pk == bob.public().kem_pk,
        keywrap::unwrap(&wrapping_key, &blob, b"eve").err());
    Ok(())
}
