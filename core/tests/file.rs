//! File format tests: round trip, and every failure case must be rejected.

use sealdrop_core::{
    Error,
    file::{self, HEADER_LEN},
    identity::SecretIdentity,
    sign::SIGNATURE_LEN,
};

struct People {
    alice: SecretIdentity, // sender
    bob: SecretIdentity,   // recipient
    eve: SecretIdentity,   // someone else
}

fn people() -> People {
    People {
        alice: SecretIdentity::generate().unwrap(),
        bob: SecretIdentity::generate().unwrap(),
        eve: SecretIdentity::generate().unwrap(),
    }
}

fn data(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i * 31 + 7) as u8).collect()
}

#[test]
fn round_trip_many_sizes() {
    let p = people();
    let bob_pub = p.bob.public();
    let alice_vk = p.alice.public().sig_vk;
    let cs = 64u32;
    for n in [0, 1, 63, 64, 65, 128, 129, 1000] {
        let pt = data(n);
        let sealed = file::seal_with_chunk_size(&pt, &bob_pub.kem_pk, &p.alice, cs).unwrap();
        let chunks = n.div_ceil(cs as usize).max(1);
        assert_eq!(sealed.len(), HEADER_LEN + n + 16 * chunks + SIGNATURE_LEN, "size n={n}");
        assert_eq!(file::open(&sealed, &p.bob, &alice_vk).unwrap(), pt, "n={n}");
    }
}

#[test]
fn round_trip_large_default_chunks() {
    let p = people();
    let pt = data(5 * 1024 * 1024 + 123); // 5 MiB + a bit: 81 chunks
    let sealed = file::seal(&pt, &p.bob.public().kem_pk, &p.alice).unwrap();
    assert_eq!(file::open(&sealed, &p.bob, &p.alice.public().sig_vk).unwrap(), pt);
}

#[test]
fn header_is_readable_without_keys() {
    let p = people();
    let sealed = file::seal(b"hi", &p.bob.public().kem_pk, &p.alice).unwrap();
    let h = file::peek_header(&sealed).unwrap();
    assert_eq!(h.chunk_size, file::DEFAULT_CHUNK_SIZE);
    assert_eq!(h.sender_fingerprint, sealdrop_core::identity::fingerprint(&p.alice.public().sig_vk));
    assert_eq!(h.recipient_fingerprint, sealdrop_core::identity::fingerprint(&p.bob.public().kem_pk));
}

#[test]
fn wrong_recipient_key_fails() {
    let p = people();
    let sealed = file::seal(b"for bob only", &p.bob.public().kem_pk, &p.alice).unwrap();
    assert_eq!(file::open(&sealed, &p.eve, &p.alice.public().sig_vk), Err(Error::DecryptionFailed));
}

#[test]
fn every_flipped_bit_fails() {
    let p = people();
    let alice_vk = p.alice.public().sig_vk;
    let sealed = file::seal_with_chunk_size(&data(200), &p.bob.public().kem_pk, &p.alice, 64).unwrap();
    // Flip one bit in every byte of the sealed file (header, every chunk, signature).
    for pos in 0..sealed.len() {
        let mut bad = sealed.clone();
        bad[pos] ^= 1 << (pos % 8);
        assert!(file::open(&bad, &p.bob, &alice_vk).is_err(), "flip at byte {pos} was accepted");
    }
    println!("bit flips rejected: {}/{}", sealed.len(), sealed.len());
}

#[test]
fn truncated_file_fails() {
    let p = people();
    let alice_vk = p.alice.public().sig_vk;
    let sealed = file::seal_with_chunk_size(&data(300), &p.bob.public().kem_pk, &p.alice, 64).unwrap();
    for cut in [1, 15, 16, 80, SIGNATURE_LEN, SIGNATURE_LEN + 80, sealed.len() - 1, sealed.len()] {
        let short = &sealed[..sealed.len() - cut];
        assert!(file::open(short, &p.bob, &alice_vk).is_err(), "truncated by {cut} accepted");
    }
}

#[test]
fn dropping_final_chunk_is_detected_by_stream_even_without_signature() {
    // The signature already catches this; this test checks the STREAM layer by
    // itself, because a malicious *sender* can always re-sign.
    let key = [7u8; 32];
    let prefix = [9u8; file::NONCE_PREFIX_LEN];
    let body = file::encrypt_body(&key, &prefix, b"aad", &data(200), 64).unwrap();
    assert_eq!(file::decrypt_body(&key, &prefix, b"aad", &body, 64).unwrap(), data(200));
    // 200 bytes / 64 = 4 chunks (64, 64, 64, 8). Drop the last one.
    let cut = &body[..3 * (64 + 16)];
    assert_eq!(file::decrypt_body(&key, &prefix, b"aad", cut, 64), Err(Error::DecryptionFailed));
    // Swap chunks 0 and 1: counter in the nonce must catch it.
    let mut swapped = body.clone();
    let (a, b) = swapped.split_at_mut(80);
    a.swap_with_slice(&mut b[..80]);
    assert!(file::decrypt_body(&key, &prefix, b"aad", &swapped, 64).is_err());
    // Wrong AAD (i.e. a different header) must fail.
    assert!(file::decrypt_body(&key, &prefix, b"aae", &body, 64).is_err());
}

#[test]
fn wrong_version_fails() {
    let p = people();
    let mut sealed = file::seal(b"x", &p.bob.public().kem_pk, &p.alice).unwrap();
    sealed[4] = 2;
    assert_eq!(file::peek_header(&sealed), Err(Error::InvalidFormat));
    assert_eq!(file::open(&sealed, &p.bob, &p.alice.public().sig_vk), Err(Error::InvalidFormat));
    sealed[4] = 1;
    sealed[0] = b'X';
    assert_eq!(file::open(&sealed, &p.bob, &p.alice.public().sig_vk), Err(Error::InvalidFormat));
}

// ---- Milestone 2b: signature checks on whole files ----

#[test]
fn valid_signature_passes() {
    let p = people();
    let sealed = file::seal(b"signed", &p.bob.public().kem_pk, &p.alice).unwrap();
    assert!(file::open(&sealed, &p.bob, &p.alice.public().sig_vk).is_ok());
}

#[test]
fn signature_from_different_sender_fails() {
    let p = people();
    // Eve sends Bob a file, but Bob checks it against Alice's key.
    let sealed = file::seal(b"pretending to be alice", &p.bob.public().kem_pk, &p.eve).unwrap();
    assert_eq!(file::open(&sealed, &p.bob, &p.alice.public().sig_vk), Err(Error::BadSignature));
}

#[test]
fn forged_sender_fingerprint_fails() {
    // Eve signs with her key but writes Alice's fingerprint into the header.
    let p = people();
    let mut sealed = file::seal(b"x", &p.bob.public().kem_pk, &p.eve).unwrap();
    let alice_fp = sealdrop_core::identity::fingerprint(&p.alice.public().sig_vk);
    sealed[10..42].copy_from_slice(&alice_fp);
    assert_eq!(file::open(&sealed, &p.bob, &p.alice.public().sig_vk), Err(Error::BadSignature));
}

#[test]
fn changed_header_or_ciphertext_fails_signature() {
    let p = people();
    let vk = p.alice.public().sig_vk;
    let sealed = file::seal(&data(1000), &p.bob.public().kem_pk, &p.alice).unwrap();
    // Recipient fingerprint, KEM ciphertext, nonce prefix, body: all signed.
    for pos in [50, 100, 1200, HEADER_LEN + 5, sealed.len() - SIGNATURE_LEN - 1] {
        let mut bad = sealed.clone();
        bad[pos] ^= 0x80;
        assert_eq!(file::open(&bad, &p.bob, &vk), Err(Error::BadSignature), "pos {pos}");
    }
}

#[test]
fn truncated_signature_fails() {
    let p = people();
    let sealed = file::seal(&data(1000), &p.bob.public().kem_pk, &p.alice).unwrap();
    let short = &sealed[..sealed.len() - 1];
    assert!(file::open(short, &p.bob, &p.alice.public().sig_vk).is_err());
}
