package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// testAgent plays the agent side: it holds the Ed25519 key and signs assertions.
type testAgent struct {
	id   string
	priv ed25519.PrivateKey
}

func (f *grantFixture) newAgent(t *testing.T, ownerTok, name string) *testAgent {
	req, priv := validAgent(name)
	var ag Agent
	json.NewDecoder(do(t, "POST", f.srv.URL+"/api/agents", ownerTok, req).Body).Decode(&ag)
	return &testAgent{id: ag.ID, priv: priv}
}

func (ta *testAgent) actorToken(t *testing.T, aud string, mutate func(*ActorClaims)) string {
	now := time.Now()
	c := &ActorClaims{RegisteredClaims: jwt.RegisteredClaims{
		Issuer: ta.id, Subject: ta.id, Audience: jwt.ClaimStrings{aud},
		IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute)), ID: newJTI(),
	}}
	if mutate != nil {
		mutate(c)
	}
	s, err := jwt.NewWithClaims(jwt.SigningMethodEdDSA, c).SignedString(ta.priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func (ta *testAgent) dpop(t *testing.T, method, u, accessToken string) string {
	pub := ta.priv.Public().(ed25519.PublicKey)
	sum := sha256.Sum256([]byte(accessToken))
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, DPoPClaims{
		RegisteredClaims: jwt.RegisteredClaims{IssuedAt: jwt.NewNumericDate(time.Now()), ID: newJTI()},
		HTM:              method, HTU: u, ATH: b64url.EncodeToString(sum[:]),
	})
	tok.Header["typ"] = "dpop+jwt"
	tok.Header["jwk"] = map[string]string{"kty": "OKP", "crv": "Ed25519", "x": b64url.EncodeToString(pub)}
	s, err := tok.SignedString(ta.priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func (f *grantFixture) exchange(t *testing.T, grantToken, actorToken, scope string) (int, map[string]any) {
	form := url.Values{
		"grant_type": {grantTypeTokenExchange}, "subject_token": {grantToken}, "subject_token_type": {tokenTypeGrant},
		"actor_token": {actorToken}, "actor_token_type": {tokenTypeJWT},
	}
	if scope != "" {
		form.Set("scope", scope)
	}
	r, err := http.Post(f.srv.URL+"/oauth/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	json.NewDecoder(r.Body).Decode(&out)
	return r.StatusCode, out
}

func (f *grantFixture) grantFor(t *testing.T, agentID string, actions []string, ttl int) (*Grant, string) {
	r := do(t, "POST", f.srv.URL+"/api/grants", f.alice, grantReq{
		AgentID: agentID, Actions: actions, Files: []grantFileReq{{FileID: f.fileA}}, ShareWith: []string{"eve"}, TTLMinutes: ttl,
	})
	var out struct {
		Grant      *Grant `json:"grant"`
		GrantToken string `json:"grant_token"`
	}
	json.NewDecoder(r.Body).Decode(&out)
	if out.GrantToken == "" {
		t.Fatalf("no grant token (%d)", r.StatusCode)
	}
	return out.Grant, out.GrantToken
}

func TestTokenExchange(t *testing.T) {
	f := newGrantFixture(t)
	is := testIssuers[f.srv.URL]
	agent := f.newAgent(t, f.alice, "bot")
	other := f.newAgent(t, f.alice, "other bot")
	g, gt := f.grantFor(t, agent.id, []string{"list", "download"}, 60)
	aud := f.srv.URL + "/oauth/token"

	code, out := f.exchange(t, gt, agent.actorToken(t, aud, nil), "")
	if code != 200 || out["token_type"] != "DPoP" || out["issued_token_type"] != tokenTypeAccessToken {
		t.Fatalf("valid exchange: %d %v", code, out)
	}
	ac, err := is.VerifyAccessToken(out["access_token"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if ac.Subject != "alice" || ac.Act.Sub != agent.id || ac.GrantID != g.ID || ac.Scope != "list download" {
		t.Errorf("claims: sub=%s act=%s grant=%s scope=%q", ac.Subject, ac.Act.Sub, ac.GrantID, ac.Scope)
	}
	if life := ac.ExpiresAt.Sub(ac.IssuedAt.Time); life > accessTokenTTL {
		t.Errorf("access token lives %v, want <= %v", life, accessTokenTTL)
	}
	// Narrower scope is fine; wider is not.
	if code, out := f.exchange(t, gt, agent.actorToken(t, aud, nil), "list"); code != 200 || out["scope"] != "list" {
		t.Errorf("narrow scope: %d %v", code, out)
	}

	refuse := map[string]struct {
		subject, actor, scope string
		want                  string
	}{
		"scope not in grant":      {gt, agent.actorToken(t, aud, nil), "list upload", "invalid_scope"},
		"other agent uses grant":  {gt, other.actorToken(t, aud, nil), "", "invalid_grant"},
		"actor signed wrong key":  {gt, (&testAgent{id: agent.id, priv: other.priv}).actorToken(t, aud, nil), "", "invalid_client"},
		"actor wrong audience":    {gt, agent.actorToken(t, "https://evil.example/token", nil), "", "invalid_client"},
		"actor sub != iss":        {gt, agent.actorToken(t, aud, func(c *ActorClaims) { c.Subject = "agt_x" }), "", "invalid_client"},
		"actor expired":           {gt, agent.actorToken(t, aud, func(c *ActorClaims) { c.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Minute)) }), "", "invalid_client"},
		"actor lives too long":    {gt, agent.actorToken(t, aud, func(c *ActorClaims) { c.ExpiresAt = jwt.NewNumericDate(time.Now().Add(time.Hour)) }), "", "invalid_client"},
		"tampered grant token":    {gt[:len(gt)-4] + "AAAA", agent.actorToken(t, aud, nil), "", "invalid_grant"},
		"grant token not a grant": {out["access_token"].(string), agent.actorToken(t, aud, nil), "", "invalid_grant"},
	}
	for name, c := range refuse {
		if code, out := f.exchange(t, c.subject, c.actor, c.scope); code == 200 || out["error"] != c.want {
			t.Errorf("%s: got %d %v, want error %s", name, code, out["error"], c.want)
		}
	}

	// Replaying the exact same actor token is refused.
	once := agent.actorToken(t, aud, nil)
	f.exchange(t, gt, once, "")
	if code, out := f.exchange(t, gt, once, ""); code == 200 || out["error"] != "invalid_client" {
		t.Errorf("actor token replay: %d %v", code, out)
	}

	// "Refresh" (exchanging again) stops when the grant expires.
	is.now = func() time.Time { return time.Unix(g.ExpiresAt, 0).Add(time.Second) }
	defer func() { is.now = time.Now }()
	if code, out := f.exchange(t, gt, agent.actorToken(t, aud, nil), ""); code == 200 {
		t.Errorf("exchange after grant expiry: %d %v", code, out)
	}
}

func TestAccessTokenNeverOutlivesGrant(t *testing.T) {
	f := newGrantFixture(t)
	is := testIssuers[f.srv.URL]
	agent := f.newAgent(t, f.alice, "bot")
	g, gt := f.grantFor(t, agent.id, []string{"list"}, 1) // 1 minute grant
	_, out := f.exchange(t, gt, agent.actorToken(t, f.srv.URL+"/oauth/token", nil), "")
	ac, err := is.VerifyAccessToken(out["access_token"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if ac.ExpiresAt.Unix() > g.ExpiresAt {
		t.Errorf("token expires %d after grant %d", ac.ExpiresAt.Unix(), g.ExpiresAt)
	}
}

func TestJWKSPublishesOnlyPublicKey(t *testing.T) {
	f := newGrantFixture(t)
	var jwks map[string][]map[string]string
	json.NewDecoder(do(t, "GET", f.srv.URL+"/.well-known/jwks.json", "", nil).Body).Decode(&jwks)
	k := jwks["keys"][0]
	if k["kty"] != "OKP" || k["x"] == "" || k["d"] != "" {
		t.Errorf("jwks: %v", k)
	}
}
