//! Delegating a single file to an agent.

use sealdrop_core::{Error, delegate, file, identity::SecretIdentity};

struct World {
    alice: SecretIdentity, // sender
    bob: SecretIdentity,   // recipient who delegates
    agent: SecretIdentity, // the agent's own identity
    other_agent: SecretIdentity,
    sealed: Vec<u8>,
    other_file: Vec<u8>,
}

fn world() -> World {
    let alice = SecretIdentity::generate().unwrap();
    let bob = SecretIdentity::generate().unwrap();
    let sealed = file::seal(b"granted file", &bob.public().kem_pk, &alice).unwrap();
    let other_file = file::seal(b"NOT granted", &bob.public().kem_pk, &alice).unwrap();
    World {
        alice,
        bob,
        agent: SecretIdentity::generate().unwrap(),
        other_agent: SecretIdentity::generate().unwrap(),
        sealed,
        other_file,
    }
}

fn wrap(w: &World, sealed: &[u8], file_id: &str, agent_id: &str, agent: &SecretIdentity) -> Vec<u8> {
    let key = file::file_key(sealed, &w.bob, &w.alice.public().sig_vk).unwrap();
    let ctx = delegate::context(sealed, file_id, agent_id).unwrap();
    delegate::wrap_file_key(&key, &agent.public().kem_pk, &ctx).unwrap()
}

#[test]
fn agent_opens_granted_file() {
    let w = world();
    let blob = wrap(&w, &w.sealed, "f1", "agt_1", &w.agent);
    assert_eq!(blob.len(), delegate::BLOB_LEN);
    let ctx = delegate::context(&w.sealed, "f1", "agt_1").unwrap();
    let key = delegate::unwrap_file_key(&blob, &w.agent.kem, &ctx).unwrap();
    let pt = file::open_with_file_key(&w.sealed, &key, &w.alice.public().sig_vk).unwrap();
    assert_eq!(pt, b"granted file");
}

#[test]
fn file_key_matches_normal_open() {
    let w = world();
    let key = file::file_key(&w.sealed, &w.bob, &w.alice.public().sig_vk).unwrap();
    assert_eq!(
        file::open_with_file_key(&w.sealed, &key, &w.alice.public().sig_vk).unwrap(),
        file::open(&w.sealed, &w.bob, &w.alice.public().sig_vk).unwrap()
    );
}

#[test]
fn other_agent_cannot_unwrap() {
    let w = world();
    let blob = wrap(&w, &w.sealed, "f1", "agt_1", &w.agent);
    let ctx = delegate::context(&w.sealed, "f1", "agt_1").unwrap();
    assert_eq!(delegate::unwrap_file_key(&blob, &w.other_agent.kem, &ctx).err(), Some(Error::DecryptionFailed));
}

#[test]
fn wrapped_key_is_bound_to_file_and_ids() {
    let w = world();
    let blob = wrap(&w, &w.sealed, "f1", "agt_1", &w.agent);
    for (sealed, fid, aid) in [(&w.other_file, "f1", "agt_1"), (&w.sealed, "f2", "agt_1"), (&w.sealed, "f1", "agt_2")] {
        let ctx = delegate::context(sealed, fid, aid).unwrap();
        assert!(delegate::unwrap_file_key(&blob, &w.agent.kem, &ctx).is_err(), "{fid} {aid}");
    }
}

#[test]
fn file_key_does_not_open_other_files() {
    let w = world();
    let key = file::file_key(&w.sealed, &w.bob, &w.alice.public().sig_vk).unwrap();
    assert!(file::open_with_file_key(&w.other_file, &key, &w.alice.public().sig_vk).is_err());
}

#[test]
fn signature_still_checked_before_decrypting() {
    let w = world();
    let key = file::file_key(&w.sealed, &w.bob, &w.alice.public().sig_vk).unwrap();
    let mut bad = w.sealed.clone();
    bad[1500] ^= 1;
    assert_eq!(file::open_with_file_key(&bad, &key, &w.alice.public().sig_vk).err(), Some(Error::BadSignature));
    assert_eq!(file::open_with_file_key(&w.sealed, &key, &w.bob.public().sig_vk).err(), Some(Error::BadSignature));
    assert!(file::file_key(&bad, &w.bob, &w.alice.public().sig_vk).is_err());
}

#[test]
fn every_flipped_bit_of_wrapped_key_fails() {
    let w = world();
    let blob = wrap(&w, &w.sealed, "f1", "agt_1", &w.agent);
    let ctx = delegate::context(&w.sealed, "f1", "agt_1").unwrap();
    for pos in 0..blob.len() {
        let mut bad = blob.clone();
        bad[pos] ^= 1 << (pos % 8);
        assert!(delegate::unwrap_file_key(&bad, &w.agent.kem, &ctx).is_err(), "flip at {pos}");
    }
    assert!(delegate::unwrap_file_key(&blob[..blob.len() - 1], &w.agent.kem, &ctx).is_err());
}
