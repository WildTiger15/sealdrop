//! X-Wing tests: official known answer tests from draft-connolly-cfrg-xwing-kem-11
//! Appendix C, plus round trip and tampering tests.
//!
//! `tests/vectors/xwing-draft-11.json` was extracted mechanically from the
//! draft text (every field length checked against section 5.1).

use sealdrop_core::xwing::{self, SecretKey};
use subtle::ConstantTimeEq;

fn unhex<const N: usize>(s: &str) -> [u8; N] {
    hex::decode(s).expect("hex").try_into().expect("length")
}

#[test]
fn official_test_vectors() {
    let text = std::fs::read_to_string("tests/vectors/xwing-draft-11.json").expect("vectors");
    let vectors: Vec<serde_json::Value> = serde_json::from_str(&text).expect("json");
    assert_eq!(vectors.len(), 3, "draft -11 Appendix C has 3 vectors");

    let mut passed = 0;
    for v in &vectors {
        let seed: [u8; 32] = unhex(v["seed"].as_str().unwrap());
        let want_sk: [u8; 32] = unhex(v["sk"].as_str().unwrap());
        let want_pk: [u8; 1216] = unhex(v["pk"].as_str().unwrap());
        let eseed: [u8; 64] = unhex(v["eseed"].as_str().unwrap());
        let want_ct: [u8; 1120] = unhex(v["ct"].as_str().unwrap());
        let want_ss: [u8; 32] = unhex(v["ss"].as_str().unwrap());

        let (sk, pk) = xwing::generate_keypair_derand(SecretKey::from_bytes(seed));
        assert_eq!(sk.as_bytes(), &want_sk, "sk");
        assert_eq!(pk, want_pk, "pk");

        let (ss, ct) = xwing::encapsulate_derand(&pk, &eseed).expect("encapsulate");
        assert_eq!(ct, want_ct, "ct");
        assert_eq!(ss.as_bytes(), &want_ss, "ss (encapsulate)");

        let ss2 = xwing::decapsulate(&ct, &sk);
        assert_eq!(ss2.as_bytes(), &want_ss, "ss (decapsulate)");
        passed += 1;
    }
    println!("X-Wing official vectors passed: {passed}/{}", vectors.len());
}

#[test]
fn round_trip() {
    for _ in 0..20 {
        let (sk, pk) = xwing::generate_keypair().unwrap();
        let (ss, ct) = xwing::encapsulate(&pk).unwrap();
        assert!(bool::from(ss.ct_eq(&xwing::decapsulate(&ct, &sk))));
    }
}

#[test]
fn encapsulate_is_randomized() {
    let (_, pk) = xwing::generate_keypair().unwrap();
    let (ss1, ct1) = xwing::encapsulate(&pk).unwrap();
    let (ss2, ct2) = xwing::encapsulate(&pk).unwrap();
    assert_ne!(ct1, ct2);
    assert!(!bool::from(ss1.ct_eq(&ss2)));
}

#[test]
fn tampered_ciphertext_gives_different_secret() {
    let (sk, pk) = xwing::generate_keypair().unwrap();
    let (ss, ct) = xwing::encapsulate(&pk).unwrap();
    // Flip one bit in the ML-KEM part (first byte, middle, last) and in the X25519 part.
    for &pos in &[0usize, 500, 1087, 1088, 1100, 1119] {
        let mut bad = ct;
        bad[pos] ^= 0x01;
        let ss_bad = xwing::decapsulate(&bad, &sk);
        assert!(!bool::from(ss.ct_eq(&ss_bad)), "flip at byte {pos} must change the secret");
    }
}

#[test]
fn wrong_secret_key_gives_different_secret() {
    let (_, pk) = xwing::generate_keypair().unwrap();
    let (other_sk, _) = xwing::generate_keypair().unwrap();
    let (ss, ct) = xwing::encapsulate(&pk).unwrap();
    assert!(!bool::from(ss.ct_eq(&xwing::decapsulate(&ct, &other_sk))));
}

#[test]
fn invalid_mlkem_public_key_is_rejected() {
    // FIPS 203 section 7.2 modulus check: 12-bit coefficients must be < q = 3329.
    // 0xFF 0xFF ... encodes coefficients of 4095, which is invalid.
    let (_, mut pk) = xwing::generate_keypair().unwrap();
    pk[0] = 0xFF;
    pk[1] = 0xFF;
    assert!(xwing::encapsulate(&pk).is_err());
}
