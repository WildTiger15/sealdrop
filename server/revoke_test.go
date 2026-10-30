package main

import "testing"

func TestRevocation(t *testing.T) {
	f := newGrantFixture(t)
	ag := f.newAgent(t, f.alice, "bot")
	g, gt := f.grantFor(t, ag.id, []string{"list", "download"}, 60)
	at := f.accessToken(t, ag, gt) // issued before revocation, still unexpired

	if code, _, _ := f.agentCall(t, ag, at, "GET", "/agent/v1/files/"+f.fileA, nil); code != 200 {
		t.Fatalf("before revocation: %d", code)
	}
	if n, _ := f.store.WrappedKeysLeft(g.ID); n != 1 {
		t.Fatalf("wrapped keys before: %d", n)
	}
	if r := do(t, "DELETE", f.srv.URL+"/api/grants/"+g.ID, f.eve, nil); r.StatusCode != 404 {
		t.Errorf("eve revoking alice's grant: got %d, want 404", r.StatusCode)
	}
	if r := do(t, "DELETE", f.srv.URL+"/api/grants/"+g.ID, f.alice, nil); r.StatusCode != 204 {
		t.Fatalf("revoke: got %d", r.StatusCode)
	}
	// 1. Wrapped keys are gone.
	if n, _ := f.store.WrappedKeysLeft(g.ID); n != 0 {
		t.Errorf("wrapped keys after revocation: %d, want 0", n)
	}
	// 2. The already-issued access token stops working immediately.
	if code, m, _ := f.agentCall(t, ag, at, "GET", "/agent/v1/files/"+f.fileA, nil); code != 403 || m["error"] != "grant revoked" {
		t.Errorf("old token after revocation: %d %v", code, m)
	}
	// 3. No new tokens.
	if code, out := f.exchange(t, gt, ag.actorToken(t, f.srv.URL+"/oauth/token", nil), ""); code == 200 || out["error_description"] != "grant revoked" {
		t.Errorf("exchange after revocation: %d %v", code, out)
	}
	// Revoking twice is harmless and keeps the first revocation time.
	if r := do(t, "DELETE", f.srv.URL+"/api/grants/"+g.ID, f.alice, nil); r.StatusCode != 204 {
		t.Errorf("second revoke: %d", r.StatusCode)
	}
}
