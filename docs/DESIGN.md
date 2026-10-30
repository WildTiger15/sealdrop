# SealDrop design (v1)

Status: informational, not audited. Written in the style of a short RFC.

## 1. Goals

1. **Zero knowledge server.** The server stores only public keys, passkey credentials, *wrapped* private keys and sealed file blobs. It cannot decrypt files or unwrap keys.
2. **Post quantum confidentiality.** File keys come from a hybrid KEM (X25519 + ML-KEM-768). An attacker must break both to learn a file key, which protects against "harvest now, decrypt later".
3. **Post quantum authenticity.** Every file is signed with ML-DSA-65. The recipient verifies the signature before decrypting anything.
4. **No passwords.** Users sign in with passkeys. The WebAuthn PRF extension provides the key that protects their private keys. A passphrase fallback exists and is labeled weaker.
5. **Simple, checkable crypto.** Only standard primitives from maintained crates. Our code combines them by following a published spec, and the official vectors prove it.

Non-goals (v1): hiding metadata, forward secrecy for stored files, multi-device sync, groups, streaming I/O for very large files.

## 2. Components

```
 Browser (TypeScript UI)                          Go server (net/http)
 ┌──────────────────────────────┐                 ┌──────────────────────────────┐
 │ passkey.ts  WebAuthn + PRF   │── assertion ───▶│ go-webauthn: verify passkey  │
 │ main.ts     UI glue          │                 │ sessions (hashed tokens)     │
 │ ┌──────────────────────────┐ │── sealed blob ─▶│ SQLite: users, credentials,  │
 │ │ sealdrop-wasm (Rust)     │ │◀─ public keys ──│   wrapped keys, files        │
 │ │  └ sealdrop-core         │ │                 │ never sees plaintext or PRF  │
 │ └──────────────────────────┘ │                 └──────────────────────────────┘
 └──────────────────────────────┘
```

* `core/` (Rust): `xwing.rs` (hybrid KEM), `sign.rs` (ML-DSA-65), `file.rs` (file format), `keywrap.rs`, `identity.rs`.
* `wasm/`: a thin wasm-bindgen wrapper. JavaScript only moves bytes around.
* `server/`: a passkey relying party plus a blob store. `cmd/dbdump` is the zero knowledge check.
* `web/`: Vite + TypeScript, served by the Go server from the same origin (required for passkeys).

## 3. Algorithms and why

| Purpose | Choice | Why |
|---|---|---|
| KEM | X-Wing (draft-connolly-cfrg-xwing-kem-11): X25519 + ML-KEM-768, SHA3-256 combiner | A hybrid with a security proof, fixed sizes, official vectors. ML-KEM-768 is NIST category 3 |
| Signature | ML-DSA-65 (FIPS 204), hedged, context `"SealDrop v1 file"` | The NIST PQ signature standard, category 3 (matches ML-KEM-768). Hedged signing resists bad RNGs |
| KDF | HKDF-SHA256 (RFC 5869) | Standard extract-then-expand with `info` labels for domain separation |
| AEAD | XChaCha20-Poly1305 | 24 byte nonces are safe to pick at random. Fast in software and WASM, with no AES hardware dependency |
| Chunking | STREAM (Hoang et al. 2015): counter + last flag in the nonce | Stops reordering, duplication and truncation of chunks |
| Hash | SHA3-256 | Fingerprints, header hash, and the body hash that gets signed |
| Password KDF | Argon2id, 64 MiB, t=3, p=1 | Fallback only. Memory-hard, slows offline guessing |
| Passkeys | WebAuthn + PRF extension | Phishing resistant sign in. PRF gives a secret only the authenticator can produce |

Crate versions (latest stable on crates.io when chosen, 2026-10-29): `ml-kem 0.3.3`, `ml-dsa 0.1.1`, `x25519-dalek 3.0.0`, `chacha20poly1305 0.11.0`, `hkdf 0.13.0`, `sha2 0.11.1`, `sha3 0.12.0`, `shake 0.1.0`, `argon2 0.6.0`, `zeroize 1.9.1`, `subtle 2.6.1`, `getrandom 0.4.3`. All are RustCrypto or dalek crates. Go: `go-webauthn/webauthn v0.18.2`, `modernc.org/sqlite v1.61.0` (pure Go, no cgo).

## 4. Key hierarchy

```
 passkey (inside authenticator)
    │  WebAuthn PRF(salt = SHA-256("SealDrop PRF salt v1"))      [or Argon2id(passphrase, salt)]
    ▼
 PRF output (32 B, browser only, never sent to server)
    │  HKDF-SHA256(info = "SealDrop v1 PRF wrapping key")
    ▼
 wrapping key (32 B)
    │  XChaCha20-Poly1305, aad = blob prefix || username
    ▼
 secret identity (64 B) = X-Wing seed (32 B) || ML-DSA seed (32 B)      ← stored on server only wrapped
    ├── X-Wing seed ──SHAKE256──▶ ML-KEM-768 keys + X25519 key  → public: 1216 B encapsulation key
    └── ML-DSA seed ──KeyGen───▶ ML-DSA-65 signing key          → public: 1952 B verifying key

 per file:
   X-Wing Encapsulate(recipient pk) ─▶ ss (32 B), kem_ct (1120 B, in header)
   file key = HKDF-SHA256(ss, info = "SealDrop v1 file key" || SHA3-256(header))
   chunks   = XChaCha20-Poly1305(file key, nonce = prefix || i || last, aad = SHA3-256(header))
   sig      = ML-DSA-65.Sign(sender, header || SHA3-256(body), ctx = "SealDrop v1 file")
```

## 5. Message formats

### 5.1 Sealed file (`SDRP`, version 1)

| Offset | Length | Field |
|---|---|---|
| 0 | 4 | magic `SDRP` |
| 4 | 1 | version = 1 |
| 5 | 1 | suite = 1 (X-Wing / HKDF-SHA256 / XChaCha20-Poly1305 / ML-DSA-65) |
| 6 | 4 | chunk size, big endian, 1 to 16 MiB (default 64 KiB) |
| 10 | 32 | sender fingerprint = SHA3-256(sender ML-DSA vk) |
| 42 | 32 | recipient fingerprint = SHA3-256(recipient X-Wing pk) |
| 74 | 1120 | X-Wing ciphertext |
| 1194 | 19 | random nonce prefix |
| 1213 | n + 16·chunks | body: sealed chunks |
| end − 3309 | 3309 | ML-DSA-65 signature |

Fixed overhead is 1213 + 3309 = 4522 bytes, plus 16 bytes per 64 KiB chunk. Unknown versions or suites are rejected (`InvalidFormat`), so a v2 can change anything after byte 5.

**Open procedure (order matters):** parse the header and check the version → check the sender fingerprint against the expected sender key → verify the ML-DSA signature over `header || SHA3-256(body)` → only then decapsulate, derive the key and decrypt every chunk. Any failure returns an error and no plaintext.

### 5.2 Wrapped identity (`SDKW`, version 1)

`magic(4) || version(1) || kdf(1: 1 = PRF, 2 = passphrase) || salt(16) || nonce(24) || AEAD(64 B identity) (80 B)` = 126 bytes. AAD = the first 46 bytes plus the username, so blobs can't be swapped between accounts.

### 5.3 Server API

| Method | Path | Auth | Notes |
|---|---|---|---|
| POST | `/api/register/begin`, `/finish` | none | passkey creation, PRF requested |
| POST | `/api/login/begin`, `/finish` | none | passkey assertion, PRF eval requested |
| GET | `/api/me` | session | username, wrapped keys |
| PUT | `/api/me/keys` | session | public keys + wrapped keys, **set once** |
| GET | `/api/users/{name}/keys` | none | public keys only |
| POST | `/api/files` | session | sealed blob (checked for magic and size only) |
| GET | `/api/files`, `/api/files/{id}` | session | only the sender or recipient |

## 6. Decisions worth defending

* **Why verify before decrypt?** The receiver touches secret keys only for authenticated input, which shrinks the attack surface and blocks oracle attacks.
* **Why sign `header || hash(body)` and not the plaintext?** The signature can be checked without decrypting, and it binds the KEM ciphertext, so nobody can re-target or re-key a file under the sender's signature.
* **Why fingerprints in the header?** The recipient learns which sender key to fetch, and a mismatch fails fast. They're public metadata, and the threat model says so.
* **Why are public keys set once?** A stolen session cookie can't replace a victim's public key with the attacker's.
* **Why does the client choose the PRF salt?** It doesn't trust a server-supplied salt. The wrapping key depends only on the passkey.
* **Why strip PRF results before sending the assertion?** `toJSON()` would include the PRF output, and that would hand the server the key to every wrapped identity.
