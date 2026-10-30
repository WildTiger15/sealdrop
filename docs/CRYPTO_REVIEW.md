# Crypto hygiene review (self review, not an audit)

Each rule from PLAN.md checked against the code, with file and line references (as of the Milestone 6 commit).

## 1. No home-made primitives

| Check | Status | Where |
|---|---|---|
| ML-KEM-768 from RustCrypto `ml-kem` | ✅ | core/src/xwing.rs:11, :101, :204, :250 |
| X25519 from `x25519-dalek` | ✅ | core/src/xwing.rs:17, :106–108 |
| SHAKE256 / SHA3-256 from `shake` / `sha3` | ✅ | core/src/xwing.rs:93–95, :121–131 |
| ML-DSA-65 from RustCrypto `ml-dsa` | ✅ | core/src/sign.rs:8, :55–59, :67–75 |
| AEAD, HKDF, Argon2 from RustCrypto | ✅ | core/src/file.rs:36–41, core/src/keywrap.rs:18–24 |
| Our code only combines them, quoting the spec | ✅ | Every function in core/src/xwing.rs quotes draft-11 §5.2–5.5 pseudocode |
| Passkey verification from `go-webauthn` | ✅ | server/auth.go (BeginRegistration/FinishRegistration/BeginLogin/FinishLogin) |

## 2. Proven by official vectors

| Vectors | Result | Where |
|---|---|---|
| X-Wing draft-11 Appendix C (keygen, encaps, decaps) | 3/3 | core/tests/xwing.rs, outputs/core-tests.txt |
| NIST ACVP ML-DSA-65 keyGen | 25/25 | core/tests/mldsa.rs |
| NIST ACVP ML-DSA-65 sigGen (pure external, internal, external-μ deterministic) | 75/75 | core/tests/mldsa.rs |
| NIST ACVP ML-DSA-65 sigVer (incl. 36 must-reject cases) | 45/45 | core/tests/mldsa.rs |

No test was weakened. Excluded on purpose (SealDrop never uses them): HashML-DSA (pre-hash) groups and the randomized external-μ sigGen group. The vector file records that note and the ACVP-Server commit it came from.

## 3. Wipe secrets after use (`zeroize`)

| Secret | How it is wiped | Where |
|---|---|---|
| X-Wing seed | `SecretKey` derives `Zeroize, ZeroizeOnDrop` | core/src/xwing.rs:46 |
| SHAKE256 expansion (96 B) | `Zeroizing` | core/src/xwing.rs:92 |
| ML-KEM seed d‖z | explicit `zeroize()` | core/src/xwing.rs:102 |
| X25519 secret bytes, ephemeral key | `Zeroizing`; `StaticSecret` zeroizes on drop (crate `zeroize` feature) | core/src/xwing.rs:104, :194 |
| encapsulation seed (64 B) | `Zeroizing` | core/src/xwing.rs:224 |
| ML-KEM shared secret | explicit `zeroize()` | core/src/xwing.rs:211, :253 |
| X-Wing shared secret | `SharedSecret` derives `ZeroizeOnDrop` | core/src/xwing.rs:59 |
| ML-DSA seed | `SigningSeed` derives `ZeroizeOnDrop`; expanded key zeroizes in the crate | core/src/sign.rs:20 |
| file key, wrapping keys | `Zeroizing<[u8; 32]>` | core/src/file.rs:195, core/src/keywrap.rs:69, :83 |
| serialized identity, unwrapped plaintext | `Zeroizing` | core/src/identity.rs:39–51, core/src/keywrap.rs:142 |
| JS copies (identity, PRF output) | best effort `fill(0)` on sign out / after use | web/src/main.ts (`forget`, `createKeys`, `unlock`) |

## 4. Constant time comparison of secrets (`subtle`)

* `SharedSecret` implements `ConstantTimeEq` (core/src/xwing.rs:68–72), and tests compare secrets with `ct_eq`.
* AEAD tag checks happen inside `chacha20poly1305` (constant time). ML-KEM's implicit-rejection select is constant time inside `ml-kem` (`ct_select`).
* Remaining `==` / `!=` comparisons are on **public** data only: magic bytes and version (file.rs:161–165, keywrap.rs:128), fingerprints of public keys (file.rs:131), chunk counters.

## 5. No `unwrap()` on secret paths, no panics on bad input

* `core/src` and `wasm/src` contain no `unwrap`, `expect`, `panic!` or `unreachable!` (checked with grep). `#![forbid(unsafe_code)]` is set in both crates (core/src/lib.rs:10, wasm/src/lib.rs:11).
* All lengths are checked before slicing: file.rs:150–157 (`split`), :160–170 (`parse_header`), keywrap.rs:127–129; `sign::verify` takes slices and maps wrong lengths to errors (sign.rs:67–70).
* Fuzzing of decrypt, decapsulate and verify under AddressSanitizer: see outputs/results.md.

## 6. Never log or print secrets; generic errors

* No printing in library code (grep shows no `println`, `eprintln`, `dbg!`).
* `Error` has five coarse variants with fixed messages (core/src/error.rs:20–28). For example, wrong key, tampered chunk and truncation all give `DecryptionFailed`.
* WASM errors carry only that fixed message (wasm/src/lib.rs:21–23).
* The server logs only library error values, never request bodies, blobs, wrapped keys or tokens (server/auth.go, server/api.go:123). Session tokens are stored hashed (server/auth.go `hashToken`).
* The PRF output is removed from the WebAuthn response before upload (web/src/passkey.ts `stripPrf`). Without this, the server would receive the key to every wrapped identity.

## 7. Randomness

* One source: `getrandom` (OS CSPRNG / `crypto.getRandomValues`), core/src/random.rs:6–8. RNG failure is an error, never a fallback.
* ML-DSA uses hedged signing with `getrandom::SysRng` (sign.rs:58).
* The derandomized X-Wing function (`encapsulate_derand`) is compiled only for tests or the `hazmat` feature (xwing.rs:177). The production `encapsulate` always draws 64 fresh bytes (xwing.rs:224–226).

## 8. Secrets in git

* `.gitignore` excludes databases, `.env`, `*.pem`/`*.key`, build output and `server/data/`. The secret scan result is in outputs/results.md.

## 9. Agents (Milestone 7)

* **No home-made token crypto.** Tokens are signed and verified by `golang-jwt/jwt/v5` (server/oauth.go) and PyJWT (mcp/sealdrop_agent/client.py). `jwt.WithValidMethods([]string{"EdDSA"})` pins the algorithm, so `alg: none` and HS256 key confusion fail (tested in mcp/tests/attacks.py).
* **Every token is checked for** `typ`, issuer, audience, expiry and issued-at. Actor assertions and DPoP proofs have one-time `jti` values stored in `used_jti` until expiry.
* **The only server secret is the token signing key.** It's an Ed25519 seed from `SEALDROP_TOKEN_KEY`, or a 0600 file. It can sign tokens but can't decrypt anything.
* **Agent file keys are wrapped with the core library** (core/src/delegate.rs), and AEAD associated data binds each one to the file header hash, file id and agent id. Unwrapping uses `Zeroizing` buffers.
* **The CLI takes secrets only on stdin** (cli/src/main.rs) and keeps the raw input in a `Zeroizing` buffer. Unknown commands exit before reading stdin.
* **The MCP server keeps keys and tokens inside its process.** `AgentIdentity.__repr__` hides keys, and `_guard` redacts known secrets and JWT-shaped strings from every tool result (mcp/sealdrop_agent/server.py).
* **The audit log fails closed.** An allowed action that can't be audited is refused (server/agentapi.go).

## Things I would fix next

1. **Key authenticity**: pin contacts' fingerprints after first use and warn on change. Longer term, a key transparency log. Today a malicious server can substitute public keys.
2. **Code delivery**: subresource integrity / a signed, reproducible client build. Browser crypto trusts whatever JavaScript the server serves.
3. **WASM secret copies**: `to_bytes().to_vec()` (wasm/src/lib.rs:28, :100, :108) copies the identity into a non-zeroizing `Vec` that leaves Rust as a JS `Uint8Array`. Better: keep the identity inside a wasm-bindgen object in Rust memory and expose only operations.
4. **Partial plaintext on failure**: `decrypt_body` (core/src/file.rs:241–264) drops the partly decrypted buffer without zeroizing it. Wrap it in `Zeroizing`.
5. **Streaming**: `seal`/`open` hold the whole file in memory. The format is already chunked, so add a streaming API.
6. **Rate limiting** on register/login and quotas on uploads. The in-memory ceremony map also doesn't scale past one server process.
7. **Key rotation and multi-device** (each passkey wraps the identity separately).
8. **Constant-time evidence**: run a tool like `dudect` against decapsulation, at least natively.
9. **Post-quantum tokens**: move grant tokens, access tokens and DPoP to ML-DSA once JOSE registers it and the libraries support it. Today the token layer is Ed25519.
10. **Agent key protection**: the agent's state file is a 0600 JSON file. Keep it in an OS keychain or HSM instead, and support agent key rotation.
11. **Store less**: prune `used_jti` in the background (today it's pruned on each insert), and cap audit log growth.
