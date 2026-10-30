"""HTTP client for the SealDrop agent API: OAuth token exchange + DPoP.

  1. Exchange (RFC 8693): subject_token = the grant token the user gave us,
     actor_token = a JWT signed with our Ed25519 key (RFC 7523 style).
  2. Every request carries `Authorization: DPoP <access token>` and a fresh
     DPoP proof (RFC 9449) signed with the same key, so the token is useless
     to anyone without our private key.
  3. Tokens last 5 minutes; we re-exchange shortly before expiry. That only
     works while the user's grant is still valid.

All JWT signing is done by PyJWT.
"""
import base64
import hashlib
import time
import uuid

import httpx
import jwt

from . import crypto_cli
from .identity import AgentIdentity

GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange"
SUBJECT_TOKEN_TYPE = "urn:sealdrop:params:oauth:token-type:grant"
ACTOR_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt"


class AgentAPIError(Exception):
    """A refused or failed request. Carries the server's reason, never a credential."""

    def __init__(self, status: int, reason: str):
        super().__init__(f"{status}: {reason}")
        self.status = status
        self.reason = reason


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


class AgentClient:
    def __init__(self, base_url: str, ident: AgentIdentity, http: httpx.Client | None = None):
        self.base = base_url.rstrip("/")
        self.ident = ident
        self.http = http or httpx.Client(timeout=60)
        self._token = ""
        self._token_exp = 0.0
        self._user = ""

    # ---- credentials (never returned to callers) ----

    def _jwk(self) -> dict:
        return {"kty": "OKP", "crv": "Ed25519", "x": _b64url(self.ident.auth_public_raw())}

    def _actor_token(self) -> str:
        now = int(time.time())
        claims = {
            "iss": self.ident.agent_id, "sub": self.ident.agent_id, "aud": self.base + "/oauth/token",
            "iat": now, "exp": now + 60, "jti": uuid.uuid4().hex,
        }
        return jwt.encode(claims, self.ident.auth_key, algorithm="EdDSA")

    def _dpop(self, method: str, url: str, access_token: str) -> str:
        claims = {
            "htm": method, "htu": url, "iat": int(time.time()), "jti": uuid.uuid4().hex,
            "ath": _b64url(hashlib.sha256(access_token.encode()).digest()),
        }
        return jwt.encode(claims, self.ident.auth_key, algorithm="EdDSA",
                          headers={"typ": "dpop+jwt", "jwk": self._jwk()})

    def _access_token(self) -> str:
        if self._token and time.time() < self._token_exp - 30:
            return self._token
        if not self.ident.grant_token:
            raise AgentAPIError(0, "no grant: ask the user to grant this agent access")
        r = self.http.post(self.base + "/oauth/token", data={
            "grant_type": GRANT_TYPE,
            "subject_token": self.ident.grant_token, "subject_token_type": SUBJECT_TOKEN_TYPE,
            "actor_token": self._actor_token(), "actor_token_type": ACTOR_TOKEN_TYPE,
        })
        body = r.json()
        if r.status_code != 200:
            self._token = ""
            raise AgentAPIError(r.status_code, body.get("error_description") or body.get("error", "token refused"))
        self._token = body["access_token"]
        self._token_exp = time.time() + body["expires_in"]
        # Who we act for (routing only; the server enforces it from the verified token).
        self._user = jwt.decode(self._token, options={"verify_signature": False})["sub"]
        return self._token

    def _call(self, method: str, path: str, json_body: dict | None = None) -> httpx.Response:
        token = self._access_token()
        url = self.base + path
        r = self.http.request(method, url, json=json_body, headers={
            "Authorization": "DPoP " + token, "DPoP": self._dpop(method, url, token),
        })
        if r.status_code >= 400:
            try:
                reason = r.json().get("error", r.reason_phrase)
            except ValueError:
                reason = r.reason_phrase
            raise AgentAPIError(r.status_code, reason)
        return r

    def _public_keys(self, who: str) -> dict:
        path = f"/api/agents/{who[6:]}/keys" if who.startswith("agent:") else f"/api/users/{who}/keys"
        r = self.http.get(self.base + path)
        if r.status_code != 200:
            raise AgentAPIError(r.status_code, f"no public keys for {who}")
        return r.json()

    # ---- operations ----

    @property
    def acting_for(self) -> str:
        self._access_token()
        return self._user

    def list_files(self) -> list[dict]:
        return self._call("GET", "/agent/v1/files").json()

    def download(self, file_id: str) -> tuple[bytes, str]:
        """Fetch, verify the sender's ML-DSA signature, decrypt. Returns (plaintext, sender)."""
        d = self._call("GET", f"/agent/v1/files/{file_id}").json()
        sender_vk = crypto_cli.b64d(self._public_keys(d["sender"])["sig_vk"])
        pt = crypto_cli.open_delegated(
            self.ident.secret, crypto_cli.b64d(d["blob"]), crypto_cli.b64d(d["wrapped_key"]),
            sender_vk, file_id, self.ident.agent_id,
        )
        return pt, d["sender"]

    def upload(self, content: bytes) -> str:
        """Encrypt to the user we act for, sign with our own ML-DSA key, upload."""
        user_pk = crypto_cli.b64d(self._public_keys(self.acting_for)["kem_pk"])
        sealed = crypto_cli.seal(self.ident.secret, content, user_pk)
        return self._call("POST", "/agent/v1/files", {"blob": crypto_cli.b64e(sealed)}).json()["id"]

    def share(self, file_id: str, recipient: str) -> str:
        """Re-encrypt a granted file for a recipient the grant allows."""
        pt, _ = self.download(file_id)
        rcpt_pk = crypto_cli.b64d(self._public_keys(recipient)["kem_pk"])
        sealed = crypto_cli.seal(self.ident.secret, pt, rcpt_pk)
        return self._call("POST", f"/agent/v1/files/{file_id}/share",
                          {"recipient": recipient, "blob": crypto_cli.b64e(sealed)}).json()["id"]
