package main

import (
	"bytes"
	"crypto/sha3"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func baseInput() PolicyInput {
	now := time.Unix(1_800_000_000, 0)
	return PolicyInput{
		Now: now,
		Token: &AccessClaims{
			RegisteredClaims: jwt.RegisteredClaims{Subject: "alice"},
			Act:              actClaim{Sub: "agt_1"}, ClientID: "agt_1", Scope: "list download share", GrantID: "grt_1",
		},
		Grant: &Grant{
			ID: "grt_1", Username: "alice", AgentID: "agt_1", Actions: []string{"list", "download", "share"},
			FileIDs: []string{"f1", "f2"}, ShareWith: []string{"bob"}, ExpiresAt: now.Unix() + 60,
		},
		Action: "download", FileID: "f1",
	}
}

// One row per branch of Decide. Each row changes exactly one thing.
func TestDecideEveryBranch(t *testing.T) {
	revoked := int64(1)
	cases := []struct {
		name   string
		mutate func(*PolicyInput)
		allow  bool
		reason string
	}{
		{"allowed download", func(in *PolicyInput) {}, true, "allowed by grant grt_1"},
		{"allowed list", func(in *PolicyInput) { in.Action, in.FileID = "list", "" }, true, "allowed by grant grt_1"},
		{"allowed share", func(in *PolicyInput) { in.Action, in.ShareTo = "share", "bob" }, true, "allowed by grant grt_1"},
		{"auth error", func(in *PolicyInput) { in.AuthError = "bad sig" }, false, "authentication failed: bad sig"},
		{"no token", func(in *PolicyInput) { in.Token = nil }, false, "no verified token"},
		{"unknown action", func(in *PolicyInput) { in.Action = "delete" }, false, "unknown action"},
		{"grant gone", func(in *PolicyInput) { in.Grant = nil }, false, "grant not found"},
		{"grant mismatch", func(in *PolicyInput) { in.Token.GrantID = "grt_2" }, false, "token names a different grant"},
		{"other agent", func(in *PolicyInput) { in.Token.Act.Sub, in.Token.ClientID = "agt_2", "agt_2" }, false, "token was issued to a different agent"},
		{"client_id != act", func(in *PolicyInput) { in.Token.ClientID = "agt_2" }, false, "token was issued to a different agent"},
		{"other user", func(in *PolicyInput) { in.Token.Subject = "eve" }, false, "token acts for a different user"},
		{"revoked", func(in *PolicyInput) { in.Grant.RevokedAt = &revoked }, false, "grant revoked"},
		{"expired", func(in *PolicyInput) { in.Now = time.Unix(in.Grant.ExpiresAt, 0) }, false, "grant expired"},
		{"not in scope", func(in *PolicyInput) { in.Token.Scope = "list" }, false, "action not in token scope"},
		{"not granted", func(in *PolicyInput) { in.Action, in.Token.Scope = "upload", "upload" }, false, "action not granted"},
		{"file not granted", func(in *PolicyInput) { in.FileID = "f9" }, false, "file not in grant"},
		{"no file id", func(in *PolicyInput) { in.FileID = "" }, false, "file not in grant"},
		{"share file not granted", func(in *PolicyInput) { in.Action, in.FileID, in.ShareTo = "share", "f9", "bob" }, false, "file not in grant"},
		{"share to stranger", func(in *PolicyInput) { in.Action, in.ShareTo = "share", "mallory" }, false, "share recipient not allowed by grant"},
	}
	for _, c := range cases {
		in := baseInput()
		c.mutate(&in)
		d := Decide(in)
		if d.Allow != c.allow || d.Reason != c.reason {
			t.Errorf("%s: got (%v, %q), want (%v, %q)", c.name, d.Allow, d.Reason, c.allow, c.reason)
		}
	}
}

// agentCall makes a real request with an access token and a fresh DPoP proof.
func (f *grantFixture) agentCall(t *testing.T, ta *testAgent, accessToken, method, path string, body any) (int, map[string]any, []byte) {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		json.NewEncoder(&buf).Encode(body)
	}
	req, _ := http.NewRequest(method, f.srv.URL+path, &buf)
	req.Header.Set("Authorization", "DPoP "+accessToken)
	req.Header.Set("DPoP", ta.dpop(t, method, f.srv.URL+path, accessToken))
	r, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var raw bytes.Buffer
	raw.ReadFrom(r.Body)
	var m map[string]any
	json.Unmarshal(raw.Bytes(), &m)
	return r.StatusCode, m, raw.Bytes()
}

func (f *grantFixture) accessToken(t *testing.T, ta *testAgent, grantToken string) string {
	code, out := f.exchange(t, grantToken, ta.actorToken(t, f.srv.URL+"/oauth/token", nil), "")
	if code != 200 {
		t.Fatalf("exchange: %d %v", code, out)
	}
	return out["access_token"].(string)
}

// agentSealed builds a blob that names the agent as signer in its header.
func agentSealed(t *testing.T, f *grantFixture, agentID string) []byte {
	ag, err := f.store.AgentByID(agentID)
	if err != nil {
		t.Fatal(err)
	}
	b := fakeSealed()
	fp := sha3.Sum256(ag.SigVK)
	copy(b[10:42], fp[:])
	return b
}

func TestAgentAPIGoesThroughPolicy(t *testing.T) {
	f := newGrantFixture(t)
	ag := f.newAgent(t, f.alice, "bot")
	_, gt := f.grantFor(t, ag.id, []string{"list", "download", "upload", "share"}, 60)
	at := f.accessToken(t, ag, gt)

	// list: only the granted file (fileA), not fileB.
	_, _, raw := f.agentCall(t, ag, at, "GET", "/agent/v1/files", nil)
	var list []FileMeta
	json.Unmarshal(raw, &list)
	if len(list) != 1 || list[0].ID != f.fileA {
		t.Errorf("list: %s", raw)
	}
	if code, _, _ := f.agentCall(t, ag, at, "GET", "/agent/v1/files/"+f.fileA, nil); code != 200 {
		t.Errorf("download granted file: %d", code)
	}
	if code, m, _ := f.agentCall(t, ag, at, "GET", "/agent/v1/files/"+f.fileB, nil); code != 403 || m["error"] != "file not in grant" {
		t.Errorf("download ungranted file: %d %v", code, m)
	}
	// upload goes to alice, signed by the agent's key.
	if code, m, _ := f.agentCall(t, ag, at, "POST", "/agent/v1/files", uploadBody{Blob: agentSealed(t, f, ag.id)}); code != 200 {
		t.Errorf("upload: %d %v", code, m)
	}
	if code, m, _ := f.agentCall(t, ag, at, "POST", "/agent/v1/files", uploadBody{Blob: fakeSealed()}); code != 400 {
		t.Errorf("upload not signed by agent: %d %v", code, m)
	}
	// share: only to eve (allowed in fixture grant), only granted files.
	if code, m, _ := f.agentCall(t, ag, at, "POST", "/agent/v1/files/"+f.fileA+"/share", shareBody{Recipient: "eve", Blob: agentSealed(t, f, ag.id)}); code != 200 {
		t.Errorf("share to allowed recipient: %d %v", code, m)
	}
	if code, m, _ := f.agentCall(t, ag, at, "POST", "/agent/v1/files/"+f.fileA+"/share", shareBody{Recipient: "bob", Blob: agentSealed(t, f, ag.id)}); code != 403 {
		t.Errorf("share to other recipient: %d %v", code, m)
	}
	// alice sees the agent's upload in her inbox, sender marked as the agent.
	var files []FileMeta
	json.NewDecoder(do(t, "GET", f.srv.URL+"/api/files", f.alice, nil).Body).Decode(&files)
	found := false
	for _, fm := range files {
		found = found || fm.Sender == "agent:"+ag.id
	}
	if !found {
		t.Error("agent upload not in alice's files")
	}
}

func TestEveryAgentRouteRequiresAToken(t *testing.T) {
	f := newGrantFixture(t)
	for _, p := range []struct{ m, path string }{
		{"GET", "/agent/v1/files"}, {"GET", "/agent/v1/files/" + f.fileA},
		{"POST", "/agent/v1/files"}, {"POST", "/agent/v1/files/" + f.fileA + "/share"},
	} {
		if r := do(t, p.m, f.srv.URL+p.path, f.alice, nil); r.StatusCode != 401 {
			t.Errorf("%s %s with a *user* session but no agent token: got %d, want 401", p.m, p.path, r.StatusCode)
		}
	}
}

func TestDPoPRequired(t *testing.T) {
	f := newGrantFixture(t)
	ag := f.newAgent(t, f.alice, "bot")
	_, gt := f.grantFor(t, ag.id, []string{"list"}, 60)
	at := f.accessToken(t, ag, gt)
	req, _ := http.NewRequest("GET", f.srv.URL+"/agent/v1/files", nil)
	req.Header.Set("Authorization", "DPoP "+at) // no proof
	if r, _ := http.DefaultClient.Do(req); r.StatusCode != 401 {
		t.Errorf("no DPoP proof: got %d, want 401", r.StatusCode)
	}
	// A proof for a different URL is rejected.
	req, _ = http.NewRequest("GET", f.srv.URL+"/agent/v1/files", nil)
	req.Header.Set("Authorization", "DPoP "+at)
	req.Header.Set("DPoP", ag.dpop(t, "GET", f.srv.URL+"/agent/v1/files/other", at))
	if r, _ := http.DefaultClient.Do(req); r.StatusCode != 401 {
		t.Errorf("DPoP for other URL: got %d, want 401", r.StatusCode)
	}
}
