package main

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
)

// grantFixture: alice and bob have keys, bob sent alice two files, alice has an agent.
type grantFixture struct {
	srv                *httptest.Server
	store              *Store
	alice, bob, eve    string
	agentID            string
	fileA, fileB, bobs string
}

func newGrantFixture(t *testing.T) *grantFixture {
	srv, store, _ := testServer(t)
	f := &grantFixture{srv: srv, store: store}
	f.alice, f.bob, f.eve = makeUser(t, store, "alice"), makeUser(t, store, "bob"), makeUser(t, store, "eve")
	for _, tok := range []string{f.alice, f.bob, f.eve} {
		do(t, "PUT", srv.URL+"/api/me/keys", tok, validKeys())
	}
	upload := func(from, to string) string {
		var up map[string]string
		json.NewDecoder(do(t, "POST", srv.URL+"/api/files", from, uploadReq{Recipient: to, Blob: fakeSealed()}).Body).Decode(&up)
		return up["id"]
	}
	f.fileA, f.fileB, f.bobs = upload(f.bob, "alice"), upload(f.bob, "alice"), upload(f.alice, "bob")
	req, _ := validAgent("helper")
	var ag Agent
	json.NewDecoder(do(t, "POST", srv.URL+"/api/agents", f.alice, req).Body).Decode(&ag)
	f.agentID = ag.ID
	return f
}

func (f *grantFixture) grant(t *testing.T, tok string, req grantReq) (int, *Grant) {
	t.Helper()
	r := do(t, "POST", f.srv.URL+"/api/grants", tok, req)
	var out struct {
		Grant *Grant `json:"grant"`
	}
	json.NewDecoder(r.Body).Decode(&out)
	return r.StatusCode, out.Grant
}

func TestGrantValidationDeniesByDefault(t *testing.T) {
	f := newGrantFixture(t)
	ok := grantReq{AgentID: f.agentID, Actions: []string{"list", "download"}, Files: []grantFileReq{{FileID: f.fileA}}, TTLMinutes: 30}
	cases := map[string]func(g *grantReq){
		"unknown agent":            func(g *grantReq) { g.AgentID = "agt_nope" },
		"no actions":               func(g *grantReq) { g.Actions = nil },
		"unknown action":           func(g *grantReq) { g.Actions = []string{"delete"} },
		"zero expiry":              func(g *grantReq) { g.TTLMinutes = 0 },
		"expiry over 24h":          func(g *grantReq) { g.TTLMinutes = 24*60 + 1 },
		"file sent by alice":       func(g *grantReq) { g.Files = []grantFileReq{{FileID: f.bobs}} },
		"nonexistent file":         func(g *grantReq) { g.Files = []grantFileReq{{FileID: "nope"}} },
		"share without recipients": func(g *grantReq) { g.Actions = []string{"share"} },
		"share to unknown user":    func(g *grantReq) { g.Actions = []string{"share"}; g.ShareWith = []string{"mallory"} },
	}
	for name, mutate := range cases {
		req := ok
		mutate(&req)
		if code, _ := f.grant(t, f.alice, req); code != 400 {
			t.Errorf("%s: got %d, want 400", name, code)
		}
	}
	if code, _ := f.grant(t, "", ok); code != 401 {
		t.Errorf("anonymous grant: got %d, want 401", code)
	}
	// bob can't grant alice's files to anyone.
	if code, _ := f.grant(t, f.bob, ok); code != 400 {
		t.Errorf("bob granting alice's file: got %d, want 400", code)
	}
	code, g := f.grant(t, f.alice, ok)
	if code != 200 || g.Username != "alice" || len(g.FileIDs) != 1 || g.FileIDs[0] != f.fileA {
		t.Fatalf("valid grant: %d %+v", code, g)
	}
	var list []*Grant
	json.NewDecoder(do(t, "GET", f.srv.URL+"/api/grants", f.alice, nil).Body).Decode(&list)
	if len(list) != 1 || list[0].ID != g.ID {
		t.Errorf("list grants: %+v", list)
	}
	json.NewDecoder(do(t, "GET", f.srv.URL+"/api/grants", f.eve, nil).Body).Decode(&list)
	if len(list) != 0 {
		t.Errorf("eve sees alice's grants")
	}
}
