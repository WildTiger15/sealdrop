# Delegated access for AI agents (Milestone 7)

Status: informational, not audited. Concepts are explained in [PRIMER_AGENTS.md](PRIMER_AGENTS.md).

## Goal

An AI agent gets **its own identity**. A user gives it **scoped, short lived, revocable** access to **specific files**. Every action is recorded as *which agent acted, for which user*. The agent never holds the user's keys or a shared long lived credential, and the server still never sees plaintext.

## Components

```
 user's browser (WASM)                Go server                          agent machine
 ─────────────────────                ─────────                          ─────────────
 register agent (public bundle) ──▶  agents                          ◀── python -m sealdrop_agent init
 create grant: files, actions,   ──▶  grants, grant_files                 (Rust CLI keygen + Ed25519 key,
   share_with, expiry; file keys        (wrapped keys only)                 private, never sent)
   wrapped to the agent in WASM  ◀──  grant token (subject token)  ──▶  set-grant
                                      /oauth/token  ◀── token exchange ── MCP server (Python, official SDK)
                                      /agent/v1/*   ◀── DPoP requests ──   │ tools: list / download /
                                       └ Decide() for every request         │ upload / share
                                      audit log, /metrics, /healthz         └ sealdrop-agent CLI (Rust core)
                                                                             ▲ stdio
                                                                           AI model (sees tool results only)
```

## Identities and keys

| Who | Key | Purpose | Where it lives |
|---|---|---|---|
| agent | X-Wing (via 32 B seed) | receive wrapped file keys | agent state file (0600), MCP process |
| agent | ML-DSA-65 (via 32 B seed) | sign files it uploads/shares | same |
| agent | Ed25519 | authenticate: actor assertions + DPoP proofs | same |
| server | Ed25519 | sign grant tokens and access tokens | `SEALDROP_TOKEN_KEY` or a 0600 file next to the DB |

The agent id (`agt_…`) is the OAuth `client_id`. The server stores only the agent's public keys and the RFC 7638 thumbprint (`jkt`) of its Ed25519 key.

## Grants (deny by default)

A grant names a user, an agent, a list of file ids (only files **sent to** that user, because those are the only ones the user can decrypt), a subset of `{list, download, upload, share}`, the users it may share to, and an expiry (1 minute to 24 hours). `share` requires `download`, since sharing means decrypting and re-encrypting. `upload` always targets the delegating user.

For `download` and `share`, the user's browser **verifies each file, recovers its 32 byte file key, and seals it to the agent's X-Wing key** (`core/src/delegate.rs`, `SDAK` v1). The associated data binds it to `SHA3-256(header)`, the file id and the agent id. A list-only grant stores no keys at all.

## Token flow (RFC 8693 + RFC 7523 + RFC 9068 + RFC 9449)

1. Creating a grant returns a **grant token**: server-signed, `typ: sealdrop-grant+jwt`, `sub` = user, `may_act.sub` = agent, `grant_id`, `exp` = grant expiry. It is useless by itself.
2. The agent calls `POST /oauth/token` with:
   * `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`
   * `subject_token` = the grant token, `subject_token_type=urn:sealdrop:params:oauth:token-type:grant`
   * `actor_token` = a JWT the agent signs with its Ed25519 key (`iss = sub = agent id`, `aud` = token endpoint, lifetime ≤ 2 minutes, one-time `jti`), `actor_token_type=urn:ietf:params:oauth:token-type:jwt`
3. The server verifies both, checks `may_act.sub` = the actor, **re-reads the grant from the database** (exists, not revoked, not expired), and checks any requested `scope` ⊆ grant actions. It then issues an **access token**:
   ```json
   { "typ": "at+jwt", "iss": "https://…", "aud": "sealdrop-agent-api", "sub": "alice",
     "act": { "sub": "agt_…" }, "client_id": "agt_…", "scope": "list download",
     "grant_id": "grt_…", "cnf": { "jkt": "<agent key thumbprint>" }, "exp": "≤ 5 min, never past the grant" }
   ```
4. Every agent request sends `Authorization: DPoP <access token>` and a fresh `DPoP` proof (`typ: dpop+jwt`, the agent's public JWK in the header, `htm`, `htu`, `iat`, one-time `jti`, `ath` = hash of the access token). The proof's key must match `cnf.jkt`, so a stolen access token is useless without the agent's private key.
5. **Refresh** = exchange again. It only works while the grant is valid.

All signing and verification uses `github.com/golang-jwt/jwt/v5` (server) and PyJWT (agent), with `EdDSA` pinned as the only accepted algorithm.

## One policy check

`server/policy.go` → `Decide(PolicyInput) Decision`: a pure function, deny by default. Every `/agent/v1` route is wrapped by `agentRoute`, which verifies the token and DPoP proof, loads the grant fresh, calls `Decide` exactly once, writes the audit row, and only then runs the handler. The checks run in this order:

auth failure → no token → unknown action → grant missing → token names another grant → token issued to another agent → token for another user → **revoked** → **expired** → action not in token scope → action not granted → file not in grant → share recipient not allowed → **allow**.

Because the grant is re-read on every request, **revocation takes effect immediately**, even for access tokens that haven't expired yet. Human (passkey session) routes keep their own simpler checks: you can fetch a file only if you sent or received it.

## Revocation

`DELETE /api/grants/{id}`: marks the grant revoked and **deletes every wrapped file key** under it, in one transaction. New token exchanges fail (`grant revoked`), and so do requests with old tokens.

## Audit and observability

* `audit` table: time, request id, actor (agent or user), user acted for, action, file, grant, allow/deny, reason. It records every agent request (unauthenticated ones as actor `unknown`), every token exchange, and every grant creation or revocation. **It fails closed:** an allowed action that can't be audited is refused. You can view it at `/audit.html`.
* Structured JSON logs (`log/slog`) with request ids, Prometheus metrics at `/metrics` (requests, latency, decisions, denials by reason, time inside `Decide`, token exchanges), and `/healthz`.

## The MCP server

`mcp/sealdrop_agent` uses the official MCP Python SDK (2.x `MCPServer`, stdio). Its tools are `list_files`, `download_file`, `upload_file` and `share_file`.

* Crypto runs in the `sealdrop-agent` Rust CLI (built from `sealdrop-core`) over stdin/stdout, so no secrets go in command-line arguments or environment variables.
* Keys, the grant token and access tokens stay inside the MCP process. Every tool result passes a guard that redacts known secrets and anything shaped like a JWT.
* File text is wrapped in `<untrusted-file-content>`, and the server instructions tell the model not to follow instructions inside files. That helps, but **the real defence is the server**: whatever the model asks for, the grant decides.

Setup:

```bash
cd mcp && python -m venv .venv && .venv/Scripts/pip install -r requirements.txt
```

```bash
python -m sealdrop_agent init --name "Research bot"
```

Paste the printed bundle into SealDrop (AI agents card) and note the agent id it assigns, then:

```bash
python -m sealdrop_agent set-agent-id agt_...
```

Create a grant in the web UI and copy the grant token into a file, then:

```bash
python -m sealdrop_agent set-grant < grant-token.txt
```

MCP client config (for example Claude Code or Claude Desktop):

```json
{ "mcpServers": { "sealdrop": { "command": "<repo>/mcp/.venv/Scripts/python",
  "args": ["-m", "sealdrop_agent", "serve"],
  "env": { "PYTHONPATH": "<repo>/mcp", "SEALDROP_URL": "https://sealdrop.onrender.com" } } } }
```

## Threats specific to agents

| Threat | Result |
|---|---|
| Replay of an expired access token / of a DPoP proof | rejected (exp, one-time jti) |
| Agent uses an action or file outside its grant | rejected by `Decide` (scope, actions, files, share list) |
| Agent A uses agent B's access token or grant token | rejected (DPoP key ≠ `cnf.jkt`; `may_act` ≠ actor) |
| Forged or edited token, `alg: none`, HS256 key confusion | rejected (EdDSA pinned, signature) |
| Access after revocation | rejected immediately (grant re-read on each request) |
| Prompt injection in a file asks the agent to fetch or share other files | the server refuses anything outside the grant, whatever the model does |
| Model tries to read credentials | no tool returns them; built-in file tools are not given to the model in our tests |

**Not protected:**
* **What the agent already read.** A file it downloaded and decrypted before revocation stays decrypted wherever the agent put it.
* **Misuse inside the grant.** An agent that is hijacked can still do anything its grant allows: read the granted files, share them with the allowed recipients, upload junk to the user. Grant narrowly.
* **A compromised agent host.** Whoever controls the machine running the MCP server controls the agent's keys.
* **Not post quantum.** The token layer uses Ed25519 (EdDSA JWTs), not post-quantum signatures, because JOSE has no ML-DSA algorithm yet in these libraries. File contents and wrapped file keys stay post quantum (X-Wing, ML-DSA-65).
* **Visible metadata.** The grant token and access tokens are signed, not encrypted: anyone who sees one learns the user name, agent id and grant id.
