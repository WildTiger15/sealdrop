# SealDrop threat model

Scope: SealDrop v1 (core, WASM client, Go server). Not audited.

## Assets

| Asset | Where it lives |
|---|---|
| File contents | sender's browser (before upload), recipient's browser (after decrypt) |
| User private keys (64 B identity) | browser memory while signed in; server stores them only wrapped |
| Passkey and PRF secret | inside the authenticator (phone, security key, platform TPM) |
| PRF output / wrapping key | browser memory, briefly |
| Session tokens | HttpOnly cookie; server stores only SHA-256 of each |
| Metadata: usernames, who sent what to whom, sizes, times | server (plaintext) |

## Attackers and what happens

| Attacker | Can do | Protected? |
|---|---|---|
| **Server breach** (full database + disk copy) | read every row | **Files: yes.** Blobs are AEAD ciphertext under keys derived from X-Wing. **Private keys: yes for PRF users**, because the wrapping key needs the passkey. **Passphrase users: partly.** Offline guessing is possible, slowed by Argon2id. **Metadata: no**, the attacker learns the social graph, file sizes and times. Checked by `cmd/dbdump` (see outputs/e2e.txt) |
| **Malicious / compromised server** (live, controls code it serves) | serve malicious JavaScript, substitute public keys | **Not protected.** A web app can't defend against the server that serves it: modified JS can exfiltrate keys after unlock. Key substitution (the server returns its own public key for "bob") is detectable only if users compare fingerprints out of band, and v1 has no pinning or key transparency. The biggest limitation |
| **Network attacker** | read/modify traffic | Protected with HTTPS (required in production; the dev server is HTTP on localhost only). Even without TLS, blobs are encrypted and signed, but session cookies and served JS are not, so TLS is mandatory |
| **Future quantum attacker** ("harvest now, decrypt later") | records ciphertexts today, later breaks X25519 and Ed25519-class crypto | **Protected** if ML-KEM-768 holds: the X-Wing secret needs both components. Signatures: ML-DSA-65 resists forgery by quantum attackers. The passkey itself (usually ECDSA P-256) is **not** post quantum, but it guards sign in and PRF access, not stored ciphertext |
| **Malicious recipient** | has the plaintext legitimately | Can share it, of course. Cannot forge files "from" the sender (needs the sender's ML-DSA key). Cannot make a third party believe the sender sent *them* the file, because the recipient fingerprint and KEM ciphertext are signed |
| **Impersonated sender** (eve claims to be alice) | uploads a file signed with her own key and alice's fingerprint | **Protected**: `open` checks the fingerprint against alice's key, then verifies the signature. Tests: `signature_from_different_sender_fails`, `forged_sender_fingerprint_fails` |
| **Tampering** (bit flips, truncation, chunk reorder) | modify blobs at rest or in transit | **Protected**: signature, per-chunk tags and STREAM counters/last flag. A one-bit flip in every byte position of a sealed file is rejected (outputs/core-tests.txt: 4786/4786) |
| **Stolen device, locked** | has the authenticator but not the PIN/biometric | Protected by user verification (required on every ceremony) |
| **Stolen device, unlocked / malware on client** | runs code as the user | **Not protected.** It can use the passkey and read decrypted files and keys in memory |
| **Stolen session cookie** | call the API as the user | Can list/download *ciphertext*, upload files, but cannot decrypt (keys need the passkey) and cannot replace the user's public keys (set once). Can fill a user's inbox |
| **Phishing site** | fake login page | Passkeys are bound to the origin (RP ID), so a phishing domain gets nothing usable |
| **Malicious file** (parser attacks) | crafted blobs | Fixed-size parsing, no `unsafe`, fuzzed (outputs/results.md) |

## What SealDrop does NOT protect

* **Metadata**: who shares with whom, when, and how big the files are (exact size is visible: plaintext = blob − 4522 − 16·chunks).
* **A malicious server serving malicious code** (inherent to browser crypto without code signing).
* **Public key authenticity** without out of band fingerprint checks (trust on first use).
* **Forward secrecy for stored files**: if a recipient's X-Wing seed later leaks (and the wrapping is broken), all files sent to them can be decrypted. There's no key rotation in v1.
* **Deletion**: the server could keep blobs forever. A recipient keeps anything they decrypted.
* **Endpoint compromise** (malware, unlocked stolen device).
* **Denial of service / spam**: no rate limiting or quotas beyond a 64 MiB upload cap.
* **Side channels inside JS engines / WASM**: constant-time Rust code compiled to WASM is *probably* still constant time, but JIT engines make no guarantee.
* **Implementation bugs in young crates**: `ml-dsa 0.1.x` and `ml-kem 0.3.x` are unaudited. KATs show they are correct on the official inputs, not that they are side channel free.

## AI agents (Milestone 7)

Agents act only through grants. The full analysis is in [AGENTS.md](AGENTS.md#threats-specific-to-agents), and the measured attack results are in `outputs/results.md`.

| Attacker | Protected? |
|---|---|
| **Hijacked agent / prompt injection** | Limited to its grant: exact files, actions, share recipients and expiry are enforced server side by `Decide()`, whatever the model asks for. **It can still misuse what the grant allows.** |
| **Stolen agent access token** | Useless without the agent's Ed25519 key (DPoP, `cnf.jkt`), and lives at most 5 minutes |
| **Stolen grant token** | Useless without the agent's key (`may_act` + signed actor assertion), dies with the grant |
| **Malicious server** | Can refuse service or keep metadata, but still can't read files or unwrap agent file keys. It *could* mint tokens, but tokens only reach ciphertext the server already has |
| **Revoked agent** | No new tokens, existing tokens stop at the next request, wrapped keys deleted. **What it already decrypted can't be taken back** |
| **Compromised agent host** | Not protected: whoever controls it holds the agent's keys and grant tokens until revocation or expiry |
