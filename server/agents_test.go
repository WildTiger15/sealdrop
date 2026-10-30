package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"testing"
)

// RFC 8037 Appendix A.3: the JWK thumbprint of the example Ed25519 key.
func TestJWKThumbprintRFC8037(t *testing.T) {
	x, _ := base64.RawURLEncoding.DecodeString("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo")
	got := jwkThumbprint(ed25519.PublicKey(x))
	if want := "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"; got != want {
		t.Fatalf("thumbprint %s, want %s", got, want)
	}
}

func validAgent(name string) (agentReq, ed25519.PrivateKey) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	return agentReq{
		Name:    name,
		KemPK:   bytes.Repeat([]byte{4}, kemPKLen),
		SigVK:   bytes.Repeat([]byte{5}, sigVKLen),
		AuthKey: pub,
	}, priv
}

func TestRegisterAgent(t *testing.T) {
	srv, store, _ := testServer(t)
	alice := makeUser(t, store, "alice")

	req, _ := validAgent("research bot")
	if r := do(t, "POST", srv.URL+"/api/agents", "", req); r.StatusCode != 401 {
		t.Errorf("anonymous registration: got %d, want 401", r.StatusCode)
	}
	bad := req
	bad.AuthKey = bad.AuthKey[:10]
	if r := do(t, "POST", srv.URL+"/api/agents", alice, bad); r.StatusCode != 400 {
		t.Errorf("short auth key: got %d, want 400", r.StatusCode)
	}
	r := do(t, "POST", srv.URL+"/api/agents", alice, req)
	var ag Agent
	json.NewDecoder(r.Body).Decode(&ag)
	if r.StatusCode != 200 || ag.ID == "" || ag.RegisteredBy != "alice" || ag.JKT != jwkThumbprint(req.AuthKey) {
		t.Fatalf("register: %d %+v", r.StatusCode, ag)
	}
	var keys map[string]string
	json.NewDecoder(do(t, "GET", srv.URL+"/api/agents/"+ag.ID+"/keys", "", nil).Body).Decode(&keys)
	if keys["kem_pk"] == "" || keys["sig_vk"] == "" {
		t.Errorf("public agent keys missing: %v", keys)
	}
	var mine []Agent
	json.NewDecoder(do(t, "GET", srv.URL+"/api/agents", alice, nil).Body).Decode(&mine)
	if len(mine) != 1 || mine[0].ID != ag.ID {
		t.Errorf("my agents: %+v", mine)
	}
}
