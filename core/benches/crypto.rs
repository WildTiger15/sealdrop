//! Criterion benchmarks: post quantum (X-Wing, ML-DSA-65) vs classic
//! (X25519, Ed25519), plus file encryption throughput.
//!
//! Run: `cargo bench -p sealdrop-core`

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use ed25519_dalek::{Signer, SigningKey as EdSigningKey, Verifier};
use hkdf::Hkdf;
use sealdrop_core::{file, identity::SecretIdentity, sign, xwing};
use sha2::Sha256;
use sha3::{Digest, Sha3_256};
use x25519_dalek::{PublicKey, StaticSecret};

fn kem(c: &mut Criterion) {
    let mut g = c.benchmark_group("kem");
    g.bench_function("xwing/keygen", |b| b.iter(|| xwing::generate_keypair().unwrap()));
    let (sk, pk) = xwing::generate_keypair().unwrap();
    g.bench_function("xwing/encapsulate", |b| b.iter(|| xwing::encapsulate(black_box(&pk)).unwrap()));
    let (_, ct) = xwing::encapsulate(&pk).unwrap();
    g.bench_function("xwing/decapsulate", |b| b.iter(|| xwing::decapsulate(black_box(&ct), &sk)));

    // Classic baseline: X25519 used as a KEM (ephemeral-static DH).
    g.bench_function("x25519/keygen", |b| {
        b.iter(|| {
            let s = StaticSecret::random();
            PublicKey::from(&s)
        })
    });
    let rs = StaticSecret::random();
    let rpk = PublicKey::from(&rs);
    g.bench_function("x25519/encapsulate", |b| {
        b.iter(|| {
            let e = StaticSecret::random();
            let ct = PublicKey::from(&e);
            (ct, e.diffie_hellman(black_box(&rpk)))
        })
    });
    let epk = PublicKey::from(&StaticSecret::random());
    g.bench_function("x25519/decapsulate", |b| b.iter(|| rs.diffie_hellman(black_box(&epk))));
    g.finish();
}

fn signatures(c: &mut Criterion) {
    let mut g = c.benchmark_group("sig");
    let msg = [0x42u8; 1245]; // header (1213) + body hash (32): what SealDrop signs
    g.bench_function("mldsa65/keygen", |b| {
        b.iter(|| sign::generate().unwrap().verifying_key())
    });
    let seed = sign::generate().unwrap();
    let vk = seed.verifying_key();
    g.bench_function("mldsa65/sign", |b| b.iter(|| sign::sign(&seed, black_box(&msg), b"bench").unwrap()));
    let sig = sign::sign(&seed, &msg, b"bench").unwrap();
    g.bench_function("mldsa65/verify", |b| {
        b.iter(|| sign::verify(&vk, black_box(&msg), b"bench", &sig).unwrap())
    });

    let mut ed_seed = [0u8; 32];
    getrandom::fill(&mut ed_seed).unwrap();
    g.bench_function("ed25519/keygen", |b| b.iter(|| EdSigningKey::from_bytes(black_box(&ed_seed)).verifying_key()));
    let ed = EdSigningKey::from_bytes(&ed_seed);
    let ed_vk = ed.verifying_key();
    g.bench_function("ed25519/sign", |b| b.iter(|| ed.sign(black_box(&msg))));
    let ed_sig = ed.sign(&msg);
    g.bench_function("ed25519/verify", |b| b.iter(|| ed_vk.verify(black_box(&msg), &ed_sig).unwrap()));
    g.finish();
}

fn file_encryption(c: &mut Criterion) {
    let mut g = c.benchmark_group("file");
    g.sample_size(20);
    let alice = SecretIdentity::generate().unwrap();
    let bob = SecretIdentity::generate().unwrap();
    let bob_pk = bob.public().kem_pk;
    let alice_vk = alice.public().sig_vk;
    let classic_rs = StaticSecret::random();
    let classic_rpk = PublicKey::from(&classic_rs);

    let mut ed_seed = [0u8; 32];
    getrandom::fill(&mut ed_seed).unwrap();
    let ed = EdSigningKey::from_bytes(&ed_seed);

    for size in [64 * 1024, 1024 * 1024, 16 * 1024 * 1024] {
        let pt = vec![0xA5u8; size];
        g.throughput(Throughput::Bytes(size as u64));

        // Full SealDrop: X-Wing + HKDF + STREAM XChaCha20-Poly1305 + ML-DSA-65 sign.
        g.bench_with_input(BenchmarkId::new("sealdrop_seal", size), &pt, |b, pt| {
            b.iter(|| file::seal(black_box(pt), &bob_pk, &alice).unwrap())
        });
        let sealed = file::seal(&pt, &bob_pk, &alice).unwrap();
        g.bench_with_input(BenchmarkId::new("sealdrop_open", size), &sealed, |b, s| {
            b.iter(|| file::open(black_box(s), &bob, &alice_vk).unwrap())
        });

        // Classic only: X25519 + HKDF + the same STREAM body, unsigned.
        g.bench_with_input(BenchmarkId::new("classic_x25519_encrypt", size), &pt, |b, pt| {
            b.iter(|| {
                let e = StaticSecret::random();
                let ss = e.diffie_hellman(&classic_rpk);
                let mut key = [0u8; 32];
                Hkdf::<Sha256>::new(None, ss.as_bytes()).expand(b"classic", &mut key).unwrap();
                file::encrypt_body(&key, &[0u8; file::NONCE_PREFIX_LEN], b"", black_box(pt), file::DEFAULT_CHUNK_SIZE)
                    .unwrap()
            })
        });

        // Classic, same shape as SealDrop: X25519 + HKDF + STREAM body
        // + SHA3-256(body) + Ed25519 signature. Isolates the post quantum cost.
        g.bench_with_input(BenchmarkId::new("classic_x25519_ed25519_seal", size), &pt, |b, pt| {
            b.iter(|| {
                let e = StaticSecret::random();
                let ss = e.diffie_hellman(&classic_rpk);
                let mut key = [0u8; 32];
                Hkdf::<Sha256>::new(None, ss.as_bytes()).expand(b"classic", &mut key).unwrap();
                let body = file::encrypt_body(&key, &[0u8; file::NONCE_PREFIX_LEN], b"", black_box(pt), file::DEFAULT_CHUNK_SIZE)
                    .unwrap();
                let digest = Sha3_256::digest(&body);
                (body, ed.sign(&digest))
            })
        });
    }
    g.finish();
}

criterion_group!(benches, kem, signatures, file_encryption);
criterion_main!(benches);
