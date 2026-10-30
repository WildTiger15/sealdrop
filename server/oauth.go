package main

// oauth.go: short lived, scoped, sender constrained tokens for agents.
//
// Standards used (all signing and verification is done by golang-jwt):
//   - RFC 8693 OAuth 2.0 Token Exchange: the agent trades
//       subject_token = a grant token (who it acts for, signed by us), plus
//       actor_token   = a JWT signed with the agent's own Ed25519 key (who it is)
//     for an access token whose `act` claim records "agent X acting for user Y".
//   - RFC 7523 style client assertion as the actor token (no shared secret).
//   - RFC 9068 JWT access tokens (typ "at+jwt"), 5 minutes long.
//   - RFC 9449 DPoP: the access token carries cnf.jkt, the thumbprint of the
//     agent's key, and every request must carry a fresh proof signed with that
//     key. A stolen access token is useless to anyone else.
// "Refreshing" is simply exchanging again: it works only while the grant is
// valid, so revoking a grant stops new tokens immediately.

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	grantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
	tokenTypeJWT           = "urn:ietf:params:oauth:token-type:jwt"
	tokenTypeAccessToken   = "urn:ietf:params:oauth:token-type:access_token"
	tokenTypeGrant         = "urn:sealdrop:params:oauth:token-type:grant" // RFC 8693 §3 allows custom URIs

	accessTokenTTL  = 5 * time.Minute
	maxAssertionAge = 2 * time.Minute // actor tokens and DPoP proofs must be this fresh
	clockLeeway     = 5 * time.Second
	agentAudience   = "sealdrop-agent-api"
)

const oauthSchema = `
CREATE TABLE IF NOT EXISTS used_jti (
	jti        TEXT PRIMARY KEY,   -- one-time ids of actor tokens and DPoP proofs (replay protection)
	expires_at INTEGER NOT NULL
);
`

// Issuer signs and verifies every token. Its Ed25519 key is the only secret
// the server holds; it signs tokens, it can't decrypt anything.
type Issuer struct {
	priv   ed25519.PrivateKey
	pub    ed25519.PublicKey
	kid    string
	origin string // e.g. https://sealdrop.onrender.com (the "iss" value)
	store  *Store
	now    func() time.Time
}

// LoadOrCreateIssuer reads the signing key from SEALDROP_TOKEN_KEY (base64
// seed) or a 0600 file next to the database, creating one if needed.
func LoadOrCreateIssuer(store *Store, origin, keyFile string) (*Issuer, error) {
	var seed []byte
	if env := os.Getenv("SEALDROP_TOKEN_KEY"); env != "" {
		s, err := base64.StdEncoding.DecodeString(env)
		if err != nil || len(s) != ed25519.SeedSize {
			return nil, errors.New("SEALDROP_TOKEN_KEY must be a base64 32 byte seed")
		}
		seed = s
	} else if b, err := os.ReadFile(keyFile); err == nil && len(b) == ed25519.SeedSize {
		seed = b
	} else {
		seed = make([]byte, ed25519.SeedSize)
		rand.Read(seed)
		if err := os.MkdirAll(filepath.Dir(keyFile), 0o700); err != nil {
			return nil, err
		}
		if err := os.WriteFile(keyFile, seed, 0o600); err != nil {
			return nil, err
		}
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	if _, err := store.db.Exec(oauthSchema); err != nil {
		return nil, err
	}
	return &Issuer{priv: priv, pub: pub, kid: jwkThumbprint(pub), origin: origin, store: store, now: time.Now}, nil
}

func (is *Issuer) tokenEndpoint() string { return is.origin + "/oauth/token" }

func (is *Issuer) sign(typ string, claims jwt.Claims) (string, error) {
	t := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	t.Header["typ"] = typ
	t.Header["kid"] = is.kid
	return t.SignedString(is.priv)
}

// ---- claims ----

type actClaim struct {
	Sub string `json:"sub"`
}

type cnfClaim struct {
	JKT string `json:"jkt"`
}

// GrantClaims: the subject token. It says "user Y allows agent X (may_act) under grant G".
type GrantClaims struct {
	jwt.RegisteredClaims
	MayAct  actClaim `json:"may_act"`
	GrantID string   `json:"grant_id"`
}

// AccessClaims: what the agent presents on every request.
type AccessClaims struct {
	jwt.RegisteredClaims
	Act      actClaim `json:"act"`
	ClientID string   `json:"client_id"`
	Scope    string   `json:"scope"`
	GrantID  string   `json:"grant_id"`
	Cnf      cnfClaim `json:"cnf"`
}

// ActorClaims: the agent's self-signed assertion of who it is.
type ActorClaims struct {
	jwt.RegisteredClaims
}

// DPoPClaims: a per-request proof of possession (RFC 9449 §4.2).
type DPoPClaims struct {
	jwt.RegisteredClaims
	HTM string `json:"htm"`
	HTU string `json:"htu"`
	ATH string `json:"ath"`
}

func newJTI() string { return randomToken()[:32] }

// MintGrantToken is called when a user creates a grant. It expires with the grant.
func (is *Issuer) MintGrantToken(g *Grant) (string, error) {
	return is.sign("sealdrop-grant+jwt", GrantClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: is.origin, Subject: g.Username, Audience: jwt.ClaimStrings{is.tokenEndpoint()},
			IssuedAt: jwt.NewNumericDate(time.Unix(g.CreatedAt, 0)), ExpiresAt: jwt.NewNumericDate(time.Unix(g.ExpiresAt, 0)),
			ID: newJTI(),
		},
		MayAct: actClaim{Sub: g.AgentID}, GrantID: g.ID,
	})
}

func (is *Issuer) parserOpts(extra ...jwt.ParserOption) []jwt.ParserOption {
	return append([]jwt.ParserOption{
		jwt.WithValidMethods([]string{"EdDSA"}), // never trust the token's own "alg"
		jwt.WithLeeway(clockLeeway),
		jwt.WithTimeFunc(is.now),
		jwt.WithIssuedAt(),
	}, extra...)
}

func checkTyp(t *jwt.Token, want string) error {
	if typ, _ := t.Header["typ"].(string); !strings.EqualFold(typ, want) {
		return fmt.Errorf("wrong token type %q", typ)
	}
	return nil
}

// ourKey makes sure a token was signed by this server's key, and nothing else.
func (is *Issuer) ourKey(t *jwt.Token) (any, error) { return is.pub, nil }

func (is *Issuer) verifyGrantToken(s string) (*GrantClaims, error) {
	c := &GrantClaims{}
	t, err := jwt.ParseWithClaims(s, c, is.ourKey, is.parserOpts(
		jwt.WithIssuer(is.origin), jwt.WithAudience(is.tokenEndpoint()), jwt.WithExpirationRequired())...)
	if err != nil {
		return nil, err
	}
	if err := checkTyp(t, "sealdrop-grant+jwt"); err != nil {
		return nil, err
	}
	if c.GrantID == "" || c.MayAct.Sub == "" || c.Subject == "" {
		return nil, errors.New("incomplete grant token")
	}
	return c, nil
}

// VerifyAccessToken checks signature, type, issuer, audience and expiry.
func (is *Issuer) VerifyAccessToken(s string) (*AccessClaims, error) {
	c := &AccessClaims{}
	t, err := jwt.ParseWithClaims(s, c, is.ourKey, is.parserOpts(
		jwt.WithIssuer(is.origin), jwt.WithAudience(agentAudience), jwt.WithExpirationRequired())...)
	if err != nil {
		return nil, err
	}
	if err := checkTyp(t, "at+jwt"); err != nil {
		return nil, err
	}
	if c.Subject == "" || c.Act.Sub == "" || c.GrantID == "" || c.Cnf.JKT == "" || c.ClientID != c.Act.Sub {
		return nil, errors.New("incomplete access token")
	}
	return c, nil
}

// useJTI records a one-time id; false means it was seen before (a replay).
func (is *Issuer) useJTI(jti string, exp time.Time) bool {
	if jti == "" || len(jti) > 128 {
		return false
	}
	is.store.db.Exec(`DELETE FROM used_jti WHERE expires_at < ?`, is.now().Unix())
	_, err := is.store.db.Exec(`INSERT INTO used_jti (jti, expires_at) VALUES (?, ?)`, jti, exp.Unix())
	return err == nil
}

// verifyActorToken checks the agent's own signed assertion (iss = sub = agent id).
func (is *Issuer) verifyActorToken(s string) (*Agent, error) {
	c := &ActorClaims{}
	var agent *Agent
	keyFor := func(t *jwt.Token) (any, error) {
		// Look up the key by the (not yet trusted) issuer; the signature check
		// that follows is what makes it trusted.
		ag, err := is.store.AgentByID(t.Claims.(*ActorClaims).Issuer)
		if err != nil {
			return nil, errors.New("unknown agent")
		}
		agent = ag
		return ed25519.PublicKey(ag.AuthKey), nil
	}
	if _, err := jwt.ParseWithClaims(s, c, keyFor, is.parserOpts(
		jwt.WithAudience(is.tokenEndpoint()), jwt.WithExpirationRequired())...); err != nil {
		return nil, err
	}
	if c.Subject != c.Issuer || c.IssuedAt == nil || c.ExpiresAt.Sub(c.IssuedAt.Time) > maxAssertionAge {
		return nil, errors.New("actor token must have sub = iss and live at most 2 minutes")
	}
	if !is.useJTI("act:"+c.ID, c.ExpiresAt.Time) {
		return nil, errors.New("actor token replayed")
	}
	return agent, nil
}

// VerifyDPoP checks a DPoP proof for this request and access token (RFC 9449 §4.3).
func (is *Issuer) VerifyDPoP(proof, method, url, accessToken, wantJKT string) error {
	c := &DPoPClaims{}
	var jkt string
	keyFromHeader := func(t *jwt.Token) (any, error) {
		jwk, ok := t.Header["jwk"].(map[string]any)
		if !ok || jwk["kty"] != "OKP" || jwk["crv"] != "Ed25519" {
			return nil, errors.New("DPoP jwk must be an Ed25519 OKP key")
		}
		x, _ := jwk["x"].(string)
		pub, err := b64url.DecodeString(x)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return nil, errors.New("bad DPoP jwk")
		}
		if _, private := jwk["d"]; private {
			return nil, errors.New("DPoP jwk must not contain a private key")
		}
		jkt = jwkThumbprint(pub)
		return ed25519.PublicKey(pub), nil
	}
	t, err := jwt.ParseWithClaims(proof, c, keyFromHeader, is.parserOpts()...)
	if err != nil {
		return err
	}
	if err := checkTyp(t, "dpop+jwt"); err != nil {
		return err
	}
	if jkt != wantJKT {
		return errors.New("DPoP key does not match the token's cnf.jkt")
	}
	if c.HTM != method || c.HTU != url {
		return errors.New("DPoP proof is for a different request")
	}
	sum := sha256.Sum256([]byte(accessToken))
	if c.ATH != b64url.EncodeToString(sum[:]) {
		return errors.New("DPoP proof is for a different access token")
	}
	if c.IssuedAt == nil || is.now().Sub(c.IssuedAt.Time) > maxAssertionAge {
		return errors.New("DPoP proof too old")
	}
	if !is.useJTI("dpop:"+c.ID, c.IssuedAt.Add(maxAssertionAge+clockLeeway)) {
		return errors.New("DPoP proof replayed")
	}
	return nil
}

// ---- the token endpoint ----

type oauthError struct {
	Code        string `json:"error"`
	Description string `json:"error_description"`
}

func writeOAuthError(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(oauthError{code, desc})
}

// Exchange is the decision logic of POST /oauth/token, separated from HTTP so
// it can be tested and audited. On success it returns the access token.
func (is *Issuer) Exchange(form map[string]string) (resp map[string]any, user, agentID, grantID, errCode, reason string) {
	if form["grant_type"] != grantTypeTokenExchange {
		return nil, "", "", "", "unsupported_grant_type", "only token exchange is supported"
	}
	if form["subject_token_type"] != tokenTypeGrant || form["actor_token_type"] != tokenTypeJWT {
		return nil, "", "", "", "invalid_request", "wrong subject_token_type or actor_token_type"
	}
	if t := form["requested_token_type"]; t != "" && t != tokenTypeAccessToken {
		return nil, "", "", "", "invalid_request", "only access tokens can be requested"
	}
	agent, err := is.verifyActorToken(form["actor_token"])
	if err != nil {
		return nil, "", "", "", "invalid_client", "actor token rejected: " + err.Error()
	}
	gc, err := is.verifyGrantToken(form["subject_token"])
	if err != nil {
		return nil, "", agent.ID, "", "invalid_grant", "grant token rejected: " + err.Error()
	}
	if gc.MayAct.Sub != agent.ID {
		return nil, gc.Subject, agent.ID, gc.GrantID, "invalid_grant", "this grant is for a different agent"
	}
	// The grant token only points at the grant: the database decides if it still holds.
	g, err := is.store.GrantByID(gc.GrantID)
	now := is.now()
	switch {
	case err != nil:
		return nil, gc.Subject, agent.ID, gc.GrantID, "invalid_grant", "grant not found"
	case g.Username != gc.Subject || g.AgentID != agent.ID:
		return nil, gc.Subject, agent.ID, g.ID, "invalid_grant", "grant does not match token"
	case g.RevokedAt != nil:
		return nil, g.Username, agent.ID, g.ID, "invalid_grant", "grant revoked"
	case now.Unix() >= g.ExpiresAt:
		return nil, g.Username, agent.ID, g.ID, "invalid_grant", "grant expired"
	}
	scopes := g.Actions
	if s := strings.TrimSpace(form["scope"]); s != "" {
		scopes = strings.Fields(s)
		for _, sc := range scopes {
			if !slices.Contains(g.Actions, sc) {
				return nil, g.Username, agent.ID, g.ID, "invalid_scope", "scope " + sc + " is not in the grant"
			}
		}
	}
	exp := now.Add(accessTokenTTL)
	if grantEnd := time.Unix(g.ExpiresAt, 0); grantEnd.Before(exp) {
		exp = grantEnd // a token never outlives its grant
	}
	at, err := is.sign("at+jwt", AccessClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: is.origin, Subject: g.Username, Audience: jwt.ClaimStrings{agentAudience},
			IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(exp), ID: newJTI(),
		},
		Act: actClaim{Sub: agent.ID}, ClientID: agent.ID, Scope: strings.Join(scopes, " "),
		GrantID: g.ID, Cnf: cnfClaim{JKT: agent.JKT},
	})
	if err != nil {
		return nil, g.Username, agent.ID, g.ID, "server_error", "could not sign token"
	}
	return map[string]any{
		"access_token": at, "issued_token_type": tokenTypeAccessToken, "token_type": "DPoP",
		"expires_in": int(exp.Sub(now).Seconds()), "scope": strings.Join(scopes, " "),
	}, g.Username, agent.ID, g.ID, "", "token issued"
}

// POST /oauth/token
func (a *API) Token(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "bad form body")
		return
	}
	form := map[string]string{}
	for _, k := range []string{"grant_type", "subject_token", "subject_token_type", "actor_token", "actor_token_type", "requested_token_type", "scope"} {
		form[k] = r.PostForm.Get(k)
	}
	resp, _, _, _, code, reason := a.issuer.Exchange(form)
	if resp == nil {
		status := http.StatusBadRequest
		if code == "invalid_client" {
			status = http.StatusUnauthorized
		}
		writeOAuthError(w, status, code, reason)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, resp)
}

// GET /.well-known/jwks.json: the public key that signs every token.
func (a *API) JWKS(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"keys": []map[string]string{{
		"kty": "OKP", "crv": "Ed25519", "x": b64url.EncodeToString(a.issuer.pub), "kid": a.issuer.kid, "use": "sig", "alg": "EdDSA",
	}}})
}
