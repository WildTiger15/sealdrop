"""Milestone 7 attack tests against a real SealDrop server and real agents.

Each attack class is tried several ways. An attempt counts as BLOCKED only if
the server refused it (HTTP status + reason recorded as evidence) and nothing
was disclosed. Results go to outputs/attacks.json; nothing here is estimated.

Run by web/e2e/agents.mjs (which creates users, files, agents and grants).
"""
import base64
import json
import os
import pathlib
import sys
import time
import uuid

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(pathlib.Path(__file__).parents[1]))
from sealdrop_agent.client import AgentAPIError, AgentClient, GRANT_TYPE, SUBJECT_TOKEN_TYPE, ACTOR_TOKEN_TYPE  # noqa: E402
from sealdrop_agent.identity import AgentIdentity  # noqa: E402

fx = json.loads(pathlib.Path(sys.argv[1]).read_text())
BASE = fx["origin"]
OUT = pathlib.Path(__file__).parents[2] / "outputs" / "attacks.json"
http = httpx.Client(timeout=60)
alice = httpx.Client(timeout=60, cookies={"sd_session": fx["alice_session"]})
attempts: list[dict] = []


def load(agent: dict) -> AgentIdentity:
    os.environ["SEALDROP_AGENT_HOME"] = agent["home"]
    return AgentIdentity.load()


A, B = load(fx["agent_a"]), load(fx["agent_b"])
ca, cb = AgentClient(BASE, A), AgentClient(BASE, B)


def record(attack: str, how: str, status: int, reason: str, blocked: bool) -> None:
    attempts.append({"attack": attack, "attempt": how, "status": status, "reason": reason, "blocked": blocked})
    print(f"  {'BLOCKED' if blocked else 'NOT BLOCKED'}  [{attack}] {how} -> {status} {reason}")


def raw_call(client: AgentClient, token: str, method: str, path: str, dpop: str | None = "fresh", body=None):
    url = BASE + path
    headers = {"Authorization": "DPoP " + token}
    if dpop == "fresh":
        headers["DPoP"] = client._dpop(method, url, token)
    elif dpop:
        headers["DPoP"] = dpop
    r = http.request(method, url, headers=headers, json=body)
    try:
        body = r.json()
        reason = body.get("error", "") if isinstance(body, dict) else "ok"
    except ValueError:
        reason = r.text[:80]
    return r.status_code, reason


def exchange(client: AgentClient, grant_token: str, actor_token: str | None = None, scope: str = ""):
    data = {
        "grant_type": GRANT_TYPE, "subject_token": grant_token, "subject_token_type": SUBJECT_TOKEN_TYPE,
        "actor_token": actor_token or client._actor_token(), "actor_token_type": ACTOR_TOKEN_TYPE,
    }
    if scope:
        data["scope"] = scope
    r = http.post(BASE + "/oauth/token", data=data)
    body = r.json()
    return r.status_code, body.get("error_description") or body.get("error", ""), body.get("access_token")


def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def denied(status: int) -> bool:
    return status in (400, 401, 403)


# ---------------------------------------------------------------------------
print("Attack 1: expired token replay")
r = alice.post(BASE + "/api/grants", json={"agent_id": A.agent_id, "actions": ["list"], "files": [{"file_id": fx["report_id"]}], "ttl_minutes": 1})
short = r.json()
tmp = AgentIdentity(name=A.name, secret=A.secret, auth_key=A.auth_key, agent_id=A.agent_id, grant_token=short["grant_token"])
ct = AgentClient(BASE, tmp)
token = ct._access_token()
exp = jwt.decode(token, options={"verify_signature": False})["exp"]
s, why = raw_call(ct, token, "GET", "/agent/v1/files")
print(f"  (control: same token before expiry -> {s})")
used_proof = ct._dpop("GET", BASE + "/agent/v1/files", token)
raw_call(ct, token, "GET", "/agent/v1/files", dpop=used_proof)  # first use of this proof
wait = max(0, exp - time.time()) + 7  # past expiry plus the server's 5 s clock leeway
print(f"  waiting {wait:.0f} s for the 1 minute grant and its token to expire ...")
time.sleep(wait)
s, why = raw_call(ct, token, "GET", "/agent/v1/files")
record("expired token replay", "reuse an expired access token with a fresh DPoP proof", s, why, denied(s))
s, why = raw_call(ct, token, "GET", "/agent/v1/files", dpop=used_proof)
record("expired token replay", "replay an expired token together with its old DPoP proof", s, why, denied(s))
s, why, _ = exchange(ct, short["grant_token"])
record("expired token replay", "refresh (re-exchange) after the grant expired", s, why, denied(s))
# DPoP proof replay with a still-valid token
tok_a = ca._access_token()
proof = ca._dpop("GET", BASE + "/agent/v1/files", tok_a)
raw_call(ca, tok_a, "GET", "/agent/v1/files", dpop=proof)
s, why = raw_call(ca, tok_a, "GET", "/agent/v1/files", dpop=proof)
record("expired token replay", "replay a captured DPoP proof (one-time jti)", s, why, denied(s))

# ---------------------------------------------------------------------------
print("Attack 2: an action that was not granted")
tok_b = cb._access_token()  # B: list + download on the report only
s, why = raw_call(cb, tok_b, "POST", "/agent/v1/files", body={"blob": "U0RSUA=="})
record("action not granted", "agent B uploads (grant: list, download)", s, why, denied(s))
s, why = raw_call(cb, tok_b, "POST", f"/agent/v1/files/{fx['report_id']}/share", body={"recipient": "mallory", "blob": "U0RSUA=="})
record("action not granted", "agent B shares a file", s, why, denied(s))
s, why = raw_call(cb, tok_b, "GET", f"/agent/v1/files/{fx['notes_id']}")
record("action not granted", "agent B downloads a file outside its grant", s, why, denied(s))
s, why = raw_call(ca, ca._access_token(), "GET", f"/agent/v1/files/{fx['secret_id']}")
record("action not granted", "agent A downloads the never-granted secret file", s, why, denied(s))
s, why, _ = exchange(cb, B.grant_token, scope="list download upload")
record("action not granted", "agent B asks the token endpoint for an extra scope", s, why, denied(s))
s, why = raw_call(ca, ca._access_token(), "POST", f"/agent/v1/files/{fx['report_id']}/share", body={"recipient": "mallory", "blob": "U0RSUA=="})
record("action not granted", "agent A shares to a recipient the grant does not allow", s, why, denied(s))
s, why = raw_call(ca, ca._access_token(), "DELETE", f"/agent/v1/files/{fx['report_id']}")
record("action not granted", "agent A tries an action that does not exist (delete)", s, why, s in (403, 404, 405))

# ---------------------------------------------------------------------------
print("Attack 3: agent A using agent B's token")
tok_b = cb._access_token()  # suppose A steals B's access token
s, why = raw_call(ca, tok_b, "GET", "/agent/v1/files")  # A signs the DPoP proof with A's key
record("agent A uses B's token", "B's access token with A's own DPoP proof", s, why, denied(s))
s, why = raw_call(ca, tok_b, "GET", "/agent/v1/files", dpop=None)
record("agent A uses B's token", "B's access token with no DPoP proof (bearer use)", s, why, denied(s))
s, why = raw_call(ca, tok_b, "GET", "/agent/v1/files", dpop=cb._dpop("GET", BASE + "/agent/v1/files/other", tok_b))
record("agent A uses B's token", "B's token with a stolen B proof made for another URL", s, why, denied(s))
s, why, _ = exchange(ca, B.grant_token)
record("agent A uses B's token", "B's grant token exchanged with A's own actor assertion", s, why, denied(s))
forged_actor = jwt.encode({"iss": B.agent_id, "sub": B.agent_id, "aud": BASE + "/oauth/token", "iat": int(time.time()),
                           "exp": int(time.time()) + 60, "jti": uuid.uuid4().hex}, A.auth_key, algorithm="EdDSA")
s, why, _ = exchange(ca, B.grant_token, actor_token=forged_actor)
record("agent A uses B's token", "actor assertion claiming to be B, signed with A's key", s, why, denied(s))

# ---------------------------------------------------------------------------
print("Attack 4: forged or tampered tokens")
tok_a = ca._access_token()
h, p, sig = tok_a.split(".")
claims = json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
for label, change in [("scope widened to upload share", {"scope": "list download upload share"}),
                      ("acting-for user changed to bob", {"sub": "bob"}),
                      ("expiry pushed a day ahead", {"exp": claims["exp"] + 86400}),
                      ("cnf.jkt swapped to attacker key", {"cnf": {"jkt": "A" * 43}})]:
    forged_p = b64url(json.dumps({**claims, **change}).encode())
    s, why = raw_call(ca, f"{h}.{forged_p}.{sig}", "GET", "/agent/v1/files")
    record("forged or tampered token", f"access token payload edited: {label}", s, why, denied(s))
attacker = Ed25519PrivateKey.generate()
selfmade = jwt.encode({**claims, "jti": uuid.uuid4().hex}, attacker, algorithm="EdDSA", headers={"typ": "at+jwt"})
s, why = raw_call(ca, selfmade, "GET", "/agent/v1/files")
record("forged or tampered token", "access token signed by an attacker's own key", s, why, denied(s))
none_tok = b64url(b'{"alg":"none","typ":"at+jwt"}') + "." + b64url(json.dumps(claims).encode()) + "."
s, why = raw_call(ca, none_tok, "GET", "/agent/v1/files")
record("forged or tampered token", 'alg "none" token', s, why, denied(s))
jwks = http.get(BASE + "/.well-known/jwks.json").json()["keys"][0]
hs = jwt.encode({**claims, "jti": uuid.uuid4().hex}, base64.urlsafe_b64decode(jwks["x"] + "=="), algorithm="HS256", headers={"typ": "at+jwt"})
s, why = raw_call(ca, hs, "GET", "/agent/v1/files")
record("forged or tampered token", "HS256 token keyed with the server's public key (alg confusion)", s, why, denied(s))
gclaims = jwt.decode(A.grant_token, options={"verify_signature": False})
fake_grant = jwt.encode({**gclaims, "grant_id": fx["agent_b"]["grant_id"], "jti": uuid.uuid4().hex}, attacker,
                        algorithm="EdDSA", headers={"typ": "sealdrop-grant+jwt"})
s, why, _ = exchange(ca, fake_grant)
record("forged or tampered token", "self-signed grant token naming another grant", s, why, denied(s))

# ---------------------------------------------------------------------------
print("Attack 5: access after revocation")
tok_b = cb._access_token()
s0, _ = raw_call(cb, tok_b, "GET", f"/agent/v1/files/{fx['report_id']}")
print(f"  (control: B downloads its granted file before revocation -> {s0})")
r = alice.delete(BASE + f"/api/grants/{fx['agent_b']['grant_id']}")
print(f"  alice revokes agent B's grant -> {r.status_code}")
s, why = raw_call(cb, tok_b, "GET", f"/agent/v1/files/{fx['report_id']}")
record("access after revocation", "download with a token issued before revocation", s, why, denied(s))
s, why = raw_call(cb, tok_b, "GET", "/agent/v1/files")
record("access after revocation", "list with a token issued before revocation", s, why, denied(s))
s, why, _ = exchange(cb, B.grant_token)
record("access after revocation", "get a new token (refresh) after revocation", s, why, denied(s))

# ---------------------------------------------------------------------------
blocked = sum(a["blocked"] for a in attempts)
classes = sorted({a["attack"] for a in attempts})
OUT.parent.mkdir(exist_ok=True)
prev = json.loads(OUT.read_text()) if OUT.exists() else {}
prev.update({"attempts": attempts, "blocked": blocked, "tried": len(attempts), "classes": classes})
OUT.write_text(json.dumps(prev, indent=1))
print(f"\nATTACKS: {blocked}/{len(attempts)} attempts blocked across {len(classes)} attack classes")
sys.exit(0 if blocked == len(attempts) else 1)
