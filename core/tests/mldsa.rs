//! ML-DSA-65 tests: NIST ACVP known answer tests (keyGen, sigGen, sigVer) and
//! SealDrop-level signature tests.
//!
//! `tests/vectors/ml-dsa-65-acvp.json` holds the ML-DSA-65 cases from the NIST
//! ACVP-Server `internalProjection.json` files (source commit recorded inside).
//! HashML-DSA ("preHash") cases are excluded because SealDrop does not use it.

use ml_dsa::{
    EncodedVerifyingKey, ExpandedSigningKey, ExpandedSigningKeyBytes, MlDsa65, Signature,
    SigningKey, VerifyingKey,
};
use sealdrop_core::sign;

fn bytes(v: &serde_json::Value, k: &str) -> Vec<u8> {
    hex::decode(v[k].as_str().unwrap_or("")).expect("hex")
}

fn load() -> serde_json::Value {
    let text = std::fs::read_to_string("tests/vectors/ml-dsa-65-acvp.json").expect("vectors");
    serde_json::from_str(&text).expect("json")
}

#[test]
#[allow(deprecated)] // to_expanded: needed to compare against the ACVP expanded sk
fn acvp_key_gen() {
    let v = load();
    let cases = v["keyGen"].as_array().unwrap();
    for t in cases {
        let seed: [u8; 32] = bytes(t, "seed").try_into().unwrap();
        // Through SealDrop's own wrapper:
        let vk = sign::SigningSeed::from_bytes(seed).verifying_key();
        assert_eq!(vk.as_slice(), bytes(t, "pk").as_slice(), "pk tcId {}", t["tcId"]);
        // And the expanded private key, via the crate:
        let sk = SigningKey::<MlDsa65>::from_seed(&seed.into());
        assert_eq!(sk.expanded_key().to_expanded().as_slice(), bytes(t, "sk").as_slice());
    }
    println!("ML-DSA-65 ACVP keyGen passed: {}/{}", cases.len(), cases.len());
}

#[test]
#[allow(deprecated)] // from_expanded: ACVP gives the expanded sk, not the seed
fn acvp_sig_gen() {
    let v = load();
    let cases = v["sigGen"].as_array().unwrap();
    for t in cases {
        let skb = ExpandedSigningKeyBytes::<MlDsa65>::try_from(bytes(t, "sk").as_slice()).unwrap();
        let sk = ExpandedSigningKey::<MlDsa65>::from_expanded(&skb);
        let rnd: [u8; 32] = bytes(t, "rnd").try_into().unwrap();
        let want = bytes(t, "signature");
        let sig = match (t["interface"].as_str().unwrap(), t["externalMu"].as_bool().unwrap()) {
            ("external", false) => {
                // FIPS 204 Algorithm 2: M' = 0 || |ctx| || ctx || M
                let ctx = bytes(t, "context");
                let msg = bytes(t, "message");
                let len = [0u8, ctx.len() as u8];
                sk.sign_internal(&[&len, &ctx, &msg], &rnd.into())
            }
            ("internal", false) => sk.sign_internal(&[&bytes(t, "message")], &rnd.into()),
            ("internal", true) => {
                assert_eq!(rnd, [0u8; 32], "only deterministic externalMu cases are included");
                let mu: [u8; 64] = bytes(t, "mu").try_into().unwrap();
                sk.sign_mu_deterministic(&mu.into())
            }
            other => panic!("unexpected group {other:?}"),
        };
        assert_eq!(sig.encode().as_slice(), want.as_slice(), "sigGen tcId {}", t["tcId"]);
    }
    println!("ML-DSA-65 ACVP sigGen passed: {}/{}", cases.len(), cases.len());
}

#[test]
fn acvp_sig_ver() {
    let v = load();
    let cases = v["sigVer"].as_array().unwrap();
    for t in cases {
        let pk = bytes(t, "pk");
        let sigb = bytes(t, "signature");
        let expected = t["testPassed"].as_bool().unwrap();
        let got = match (t["interface"].as_str().unwrap(), t["externalMu"].as_bool().unwrap()) {
            // External interface goes through SealDrop's own verify().
            ("external", false) => {
                sign::verify(&pk, &bytes(t, "message"), &bytes(t, "context"), &sigb).is_ok()
            }
            (iface, mu) => {
                let vk = VerifyingKey::<MlDsa65>::decode(
                    &EncodedVerifyingKey::<MlDsa65>::try_from(pk.as_slice()).unwrap(),
                );
                match Signature::<MlDsa65>::try_from(sigb.as_slice()) {
                    Err(_) => false,
                    Ok(sig) if iface == "internal" && !mu => vk.verify_internal(&bytes(t, "message"), &sig),
                    Ok(sig) => {
                        let m: [u8; 64] = bytes(t, "mu").try_into().unwrap();
                        vk.verify_mu(&m.into(), &sig)
                    }
                }
            }
        };
        assert_eq!(got, expected, "sigVer tcId {} ({})", t["tcId"], t["reason"]);
    }
    println!("ML-DSA-65 ACVP sigVer passed: {}/{}", cases.len(), cases.len());
}

#[test]
fn sign_verify_round_trip_and_failures() {
    let alice = sign::generate().unwrap();
    let mallory = sign::generate().unwrap();
    let msg = b"hello post quantum world";
    let ctx = b"test ctx";
    let sig = sign::sign(&alice, msg, ctx).unwrap();
    let vk = alice.verifying_key();

    assert!(sign::verify(&vk, msg, ctx, &sig).is_ok(), "valid signature passes");
    assert!(sign::verify(&mallory.verifying_key(), msg, ctx, &sig).is_err(), "other sender fails");
    assert!(sign::verify(&vk, b"hello post quantum worle", ctx, &sig).is_err(), "changed msg fails");
    assert!(sign::verify(&vk, msg, b"other ctx", &sig).is_err(), "changed context fails");
    assert!(sign::verify(&vk, msg, ctx, &sig[..sig.len() - 1]).is_err(), "truncated sig fails");
    assert!(sign::verify(&vk, msg, ctx, &[]).is_err(), "empty sig fails");
    assert!(sign::verify(&vk[..100], msg, ctx, &sig).is_err(), "truncated key fails");
    for pos in [0, 1000, sig.len() - 1] {
        let mut bad = sig;
        bad[pos] ^= 0x01;
        assert!(sign::verify(&vk, msg, ctx, &bad).is_err(), "flipped sig bit at {pos} fails");
    }
}
