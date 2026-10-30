//! Feed arbitrary bytes to every decryption entry point. They must return an
//! error or a value, never panic, hang or read out of bounds.
#![no_main]

use libfuzzer_sys::fuzz_target;
use sealdrop_core::{file, identity::SecretIdentity, keywrap, sign, xwing};
use std::sync::OnceLock;

struct Fixture {
    recipient: SecretIdentity,
    sender_vk: [u8; sign::VERIFYING_KEY_LEN],
    wrap_key: [u8; 32],
}

fn fixture() -> &'static Fixture {
    static F: OnceLock<Fixture> = OnceLock::new();
    F.get_or_init(|| {
        // Fixed, public test seeds: the fuzzer is not about key secrecy.
        let recipient = SecretIdentity {
            kem: xwing::SecretKey::from_bytes([1; 32]),
            sig: sign::SigningSeed::from_bytes([2; 32]),
        };
        let sender_vk = sign::SigningSeed::from_bytes([3; 32]).verifying_key();
        Fixture { recipient, sender_vk, wrap_key: [4; 32] }
    })
}

fuzz_target!(|data: &[u8]| {
    let f = fixture();
    let _ = file::peek_header(data);
    let _ = file::open(data, &f.recipient, &f.sender_vk);
    // Past the signature check: the chunked AEAD layer on its own.
    if data.len() > 4 {
        let chunk_size = u32::from(u16::from_le_bytes([data[0], data[1]])).max(1);
        let _ = file::decrypt_body(&[5; 32], &[6; file::NONCE_PREFIX_LEN], b"", &data[2..], chunk_size);
    }
    let _ = keywrap::blob_kdf(data);
    let _ = keywrap::unwrap(&f.wrap_key, data, b"user");
});
