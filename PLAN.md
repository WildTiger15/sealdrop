# Project Plan: SealDrop, post quantum end to end encrypted file sharing, unlocked with a passkey

## What this is (read first)

SealDrop is a small file sharing app where:

* Files are encrypted in the browser before upload, so the server only ever stores ciphertext (zero knowledge).
* Encryption uses a hybrid key exchange: classic X25519 combined with the NIST post quantum standard ML-KEM-768 (FIPS 203), so shared files stay safe even if one algorithm is broken later ("harvest now, decrypt later").
* Every shared file is signed by the sender with the NIST post quantum signature standard ML-DSA-65 (FIPS 204), so the recipient can prove who sent it and that nobody changed it, even against a future quantum attacker. SealDrop uses both NIST post quantum standards: ML-KEM for encryption and ML-DSA for signatures.
* There is no password. The user signs in with a passkey (WebAuthn), and the passkey PRF extension derives the key that protects the user's private keys.

Architecture:

* A Rust crypto core library (the most important part), compiled to WebAssembly for the browser.
* A Go server that stores public keys and encrypted blobs and verifies passkeys, and can never read file contents.
* A small TypeScript web client.
* A threat model, a design document and a crypto hygiene review.

This is a learning and portfolio project. It is not audited and must say so clearly in the README.

## Ground rules for Claude Code (follow strictly)

* Work one milestone at a time. Finish it, run it, show me the output, then stop and wait for me to say continue.
* Never implement cryptographic primitives yourself. Use well known, maintained crates and libraries (for example RustCrypto `ml-kem`, `ml-dsa`, `x25519-dalek`, `chacha20poly1305`, `hkdf`, `sha3`, `zeroize`, `subtle`). Check current versions on crates.io before adding them, and tell me which versions you chose and why. My code only combines them, following a published specification.
* When implementing a specification (for example the IETF X-Wing hybrid KEM draft), quote the exact section you are implementing in a comment, and follow it exactly. If the spec and a crate disagree, stop and ask me.
* Correctness is proven with official test vectors (known answer tests). Never weaken a test to make it pass.
* Never invent numbers. Every metric in the README, docs or resume must come from a real run. Use placeholders in curly braces until then.
* Secret hygiene in all code: wipe secrets from memory after use (`zeroize`), compare secrets in constant time (`subtle`), never log or print secret material, never use `unwrap()` on paths that handle secrets, return generic errors that do not leak information.
* I am new to Rust and Go and will be interviewed live without AI tools. After each milestone, explain every file you wrote in plain language: what it does, why it is safe, and what would go wrong if done differently. Keep code simple and readable over clever.
* Never commit keys, secrets or test credentials. Add a .gitignore and run a secret scan before the first push.
* Commit after each milestone with a clear message.
* If something here is unclear or a better choice exists, ask me before building.

## Tech stack

* Rust (stable) for the crypto core: `ml-kem`, `ml-dsa`, `x25519-dalek`, `chacha20poly1305` (XChaCha20-Poly1305 for file encryption), `hkdf`, `sha3`, `rand_core` with OS randomness, `zeroize`, `subtle`, `criterion` for benchmarks, `cargo-fuzz` for fuzzing, `wasm-bindgen` and `wasm-pack` for WebAssembly.
* Go (latest stable) for the server: standard library `net/http`, `github.com/go-webauthn/webauthn` for passkeys, SQLite for storage.
* TypeScript with Vite for the web client (no heavy framework needed).

## Folder structure

```
sealdrop/
  PLAN.md  README.md
  core/                 Rust crate: hybrid KEM, file encryption, key wrapping
    src/  tests/  benches/  fuzz/
  wasm/                 wasm-bindgen wrapper around core
  server/               Go server (passkeys, public keys, encrypted blobs)
  web/                  TypeScript client
  docs/
    DESIGN.md           how it works, written like a short RFC
    THREAT_MODEL.md     what it protects against and what it does not
    CRYPTO_REVIEW.md    hygiene checklist applied to my own code
    CONCEPTS.md         I write this myself in my own words
  outputs/              benchmark and test results
```

## Milestones

### Milestone 0: setup and learning
* Install Rust, wasm-pack and Go. Create the folders, .gitignore and a README stub with the "not audited" notice.
* Give me a one page plain language primer covering: what a KEM is, how X25519 and ML-KEM differ, why hybrid is used today, what an AEAD is, what HKDF does, what constant time means, and why you never write your own primitives. I will rewrite it in my own words in docs/CONCEPTS.md.
* Done when: toolchains work and the primer exists.

### Milestone 1: the hybrid KEM in Rust (the core of the project)
* Implement a hybrid KEM combining X25519 and ML-KEM-768 following the current IETF X-Wing draft (find the latest version and confirm with me before coding). Functions: generate keypair, encapsulate (produces ciphertext and shared secret), decapsulate.
* Add known answer tests using the official test vectors from the draft, plus round trip tests and tests that tampered ciphertexts do not produce the same secret.
* Done when: all official vectors pass and you report how many.

### Milestone 2: file encryption and key wrapping
* Encrypt a file for a recipient: hybrid KEM gives a shared secret, HKDF derives a file key, XChaCha20-Poly1305 encrypts the file in chunks so large files work, with a versioned header so the format can change later.
* Key wrapping: encrypt a user's private keys under a wrapping key (which will come from the passkey in milestone 5).
* Tests: round trip, wrong key fails, any flipped bit fails, truncated file fails, wrong version fails.
* Done when: the library can encrypt and decrypt files safely, with tests for every failure case.

### Milestone 2b: post quantum signatures (ML-DSA)
* Add ML-DSA-65 (FIPS 204) signing using a vetted crate. Each user gets a signing keypair alongside their encryption keypair; the signing private key is wrapped the same way as the other private keys.
* The sender signs the file header plus a hash of the full ciphertext. The recipient verifies the signature before decrypting anything, and rejects the file if verification fails.
* Tests: official ML-DSA test vectors (known answer tests), valid signature passes, a signature from a different sender fails, any change to the header or ciphertext fails, a truncated signature fails.
* Done when: signed files verify correctly, every tampering case is rejected, and you report how many official vectors passed.

### Milestone 3: benchmarks and fuzzing
* Benchmarks with criterion: keypair generation, encapsulation, decapsulation, ML-DSA signing and verification, and file encryption speed (MB/s), compared against an X25519 only version and an Ed25519 signature. Also report key, ciphertext and signature sizes for post quantum vs classic.
* Fuzz the decrypt, decapsulate and signature verify functions with cargo-fuzz for a fixed time (for example 30 minutes each) and report total executions and crashes.
* Write all numbers to outputs/results.md.
* Done when: I have real performance numbers and a fuzzing result.

### Milestone 4: WebAssembly and browser demo
* Wrap the core with wasm-bindgen. Build with wasm-pack.
* web/: a simple page where I can generate keys, encrypt a file for a recipient public key, and decrypt it, all in the browser. Measure encryption time in the browser too.
* Done when: files encrypt and decrypt in the browser with the Rust code.

### Milestone 5: Go server and passkeys
* server/: a Go server with endpoints to register and sign in with a passkey (go-webauthn), publish and fetch public keys, and upload and download encrypted blobs. It stores only public keys, passkey credentials and ciphertext.
* In the client, request the WebAuthn PRF extension at sign in and use its output (through HKDF) as the wrapping key for the user's private keys. If the browser does not support PRF, show a clear message and fall back to a local passphrase, labeled as weaker.
* Zero knowledge check: write a script that dumps the server database and shows that no file contents or private keys are readable.
* Done when: two accounts can share an encrypted file end to end, signed in with passkeys.

### Milestone 6: documents and packaging
* docs/DESIGN.md: the design written like a short RFC (goals, components, message formats, key hierarchy diagram, algorithm choices and why).
* docs/THREAT_MODEL.md: assets, attackers (server breach, network attacker, future quantum attacker, malicious recipient, impersonated sender, stolen device), what is protected, and what is not (for example metadata like file sizes and who shares with whom).
* docs/CRYPTO_REVIEW.md: go through the hygiene rules above against my own code, with file and line references, and list anything I would fix next.
* README.md: what it is, demo GIF, how to run, results table (test vectors passed, fuzz executions, benchmark numbers, size overhead), limitations, the "not audited" notice.
* Done when: a security engineer could read the repo in 5 minutes and understand the design and its limits.

### Milestone 7: identity and delegated access for AI agents
* Goal: AI agents get their own identity. A user can give an agent scoped, short lived, revocable access to specific files, and every action is recorded as which agent acted and on whose behalf. The agent never gets the user's keys or a shared long lived credential, and the server still never sees plaintext. Do not change or break anything that already works.
* First: a one page plain language primer on authentication vs authorization, OAuth 2.0 token exchange (RFC 8693) and the actor (`act`) claim, how a JWT is signed and verified, least privilege, and why long lived shared credentials are dangerous for AI agents. Wait for "continue" before writing code.
* Build in this order, committing after each step:
  1. Agent registration: each agent generates its own encryption keypair (its private key never leaves the agent) and gets its own client identity.
  2. User grants: a signed in user grants an agent access to specific files, with specific actions (list, download, upload, share) and an expiry. Deny by default.
  3. Short lived scoped tokens: the Go server issues signed JWTs a few minutes long through OAuth 2.0 token exchange, with the actor claim recording which agent acts on whose behalf. Refresh only works while the grant is valid. Use well known JWT and OAuth libraries; never write our own token signing.
  4. One policy check: a single, well tested function that every request passes through.
  5. Key wrapping: for granted files only, the user's client wraps the file key to the agent's public key.
  6. Revocation: revoking a grant stops new tokens immediately and deletes the agent's wrapped keys.
  7. Audit log: record agent, user acted for, action, file, decision and reason for every request, with a simple page to view it.
  8. MCP server in Python (new `mcp/` folder): official MCP SDK, tools for list, download, upload and share that call the Go server. Decryption via a small Rust command line tool built from the core library (no Python bindings). The agent's private key and tokens stay inside the MCP server process and are never returned in a tool result, so the model never sees a credential.
  9. Observability: structured logs with request IDs, metrics for requests, denials and latency, and a health endpoint.
  10. Attack tests, last: expired token replay; an action that was not granted; agent A using agent B's token; access after revocation; a forged or tampered token; a real agent run where a file contains a prompt injection telling the agent to fetch files outside its grant.
* Done when: report how many attacks were blocked out of how many were tried, and the median policy check time, in outputs/results.md. Never invent numbers.

## Resume lines to fill (from outputs only, never guess)

* Built a Rust library for post quantum hybrid encryption (X25519 + ML-KEM-768, IETF X-Wing draft) and post quantum signatures (ML-DSA-65), passing {N} official test vectors with {E} fuzzing executions and zero crashes
* Compiled the library to WebAssembly for an end to end encrypted file sharing app with a Go server that stores only ciphertext, using passkeys (WebAuthn PRF) instead of passwords to protect user keys
* Benchmarked hybrid key exchange at {X} ms, ML-DSA signing at {S} ms and file encryption at {Y} MB/s ({Z}x the classic only cost), and documented the design, threat model and a crypto hygiene review

## Cut order if time runs out

Cut in this order and tell me what was cut so I do not claim it: passkey PRF (use the passphrase fallback), Go server (keep the browser demo only), browser benchmarks, fuzzing. Keep ML-DSA signatures if at all possible, since using both NIST post quantum standards is a key part of the project. Never cut milestone 1, the test vectors, or the threat model, because they are the strongest parts.

## Things I must do myself

* Read and understand every file before moving on, and write docs/CONCEPTS.md in my own words.
* Be able to explain without notes: hybrid vs post quantum only, the difference between a KEM and a signature and why the file needs both, what the test vectors prove, why the server cannot read files, what the threat model does not cover.
* Record a 2 minute demo video.
