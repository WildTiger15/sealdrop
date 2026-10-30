use sealdrop_core::{
    Error,
    identity::SecretIdentity,
    keywrap::{self, KdfKind},
};

const USER: &[u8] = b"alice";

#[test]
fn prf_round_trip() {
    let id = SecretIdentity::generate().unwrap();
    let key = keywrap::wrapping_key_from_prf(&[42u8; 32]).unwrap();
    let blob = keywrap::wrap(&key, KdfKind::Prf, &[0; 16], &id, USER).unwrap();
    assert_eq!(blob.len(), keywrap::BLOB_LEN);
    let back = keywrap::unwrap(&key, &blob, USER).unwrap();
    assert_eq!(back.to_bytes().as_slice(), id.to_bytes().as_slice());
}

#[test]
fn wrong_key_fails() {
    let id = SecretIdentity::generate().unwrap();
    let key = keywrap::wrapping_key_from_prf(&[1u8; 32]).unwrap();
    let other = keywrap::wrapping_key_from_prf(&[2u8; 32]).unwrap();
    let blob = keywrap::wrap(&key, KdfKind::Prf, &[0; 16], &id, USER).unwrap();
    assert!(matches!(keywrap::unwrap(&other, &blob, USER), Err(Error::DecryptionFailed)));
}

#[test]
fn wrong_user_context_fails() {
    // The server swapping Alice's blob into Bob's account must not work.
    let id = SecretIdentity::generate().unwrap();
    let key = keywrap::wrapping_key_from_prf(&[1u8; 32]).unwrap();
    let blob = keywrap::wrap(&key, KdfKind::Prf, &[0; 16], &id, USER).unwrap();
    assert!(keywrap::unwrap(&key, &blob, b"bob").is_err());
}

#[test]
fn every_flipped_bit_fails() {
    let id = SecretIdentity::generate().unwrap();
    let key = keywrap::wrapping_key_from_prf(&[1u8; 32]).unwrap();
    let blob = keywrap::wrap(&key, KdfKind::Prf, &[0; 16], &id, USER).unwrap();
    for pos in 0..blob.len() {
        let mut bad = blob.clone();
        bad[pos] ^= 1 << (pos % 8);
        assert!(keywrap::unwrap(&key, &bad, USER).is_err(), "flip at {pos}");
    }
}

#[test]
fn truncated_and_wrong_version_fail() {
    let id = SecretIdentity::generate().unwrap();
    let key = keywrap::wrapping_key_from_prf(&[1u8; 32]).unwrap();
    let mut blob = keywrap::wrap(&key, KdfKind::Prf, &[0; 16], &id, USER).unwrap();
    assert!(keywrap::unwrap(&key, &blob[..blob.len() - 1], USER).is_err());
    blob[4] = 9;
    assert!(matches!(keywrap::unwrap(&key, &blob, USER), Err(Error::InvalidFormat)));
}

#[test]
fn short_prf_output_rejected() {
    assert!(keywrap::wrapping_key_from_prf(&[0u8; 16]).is_err());
}

#[test]
fn passphrase_round_trip() {
    let id = SecretIdentity::generate().unwrap();
    let salt = keywrap::new_salt().unwrap();
    let key = keywrap::wrapping_key_from_passphrase(b"correct horse battery staple", &salt).unwrap();
    let blob = keywrap::wrap(&key, KdfKind::Passphrase, &salt, &id, USER).unwrap();

    let (kdf, salt2) = keywrap::blob_kdf(&blob).unwrap();
    assert_eq!(kdf, KdfKind::Passphrase);
    let key2 = keywrap::wrapping_key_from_passphrase(b"correct horse battery staple", &salt2).unwrap();
    assert!(keywrap::unwrap(&key2, &blob, USER).is_ok());

    let wrong = keywrap::wrapping_key_from_passphrase(b"wrong", &salt2).unwrap();
    assert!(keywrap::unwrap(&wrong, &blob, USER).is_err());
}

#[test]
fn identity_public_keys_are_stable() {
    let id = SecretIdentity::generate().unwrap();
    let again = SecretIdentity::from_bytes(id.to_bytes().as_slice()).unwrap();
    assert_eq!(id.public().kem_pk, again.public().kem_pk);
    assert_eq!(id.public().sig_vk, again.public().sig_vk);
}
