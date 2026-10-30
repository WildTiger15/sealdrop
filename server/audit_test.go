package main

import (
	"encoding/json"
	"testing"
)

func TestAuditRecordsEveryDecision(t *testing.T) {
	f := newGrantFixture(t)
	ag := f.newAgent(t, f.alice, "bot")
	g, gt := f.grantFor(t, ag.id, []string{"list", "download"}, 60)
	at := f.accessToken(t, ag, gt)
	f.agentCall(t, ag, at, "GET", "/agent/v1/files/"+f.fileA, nil) // allow
	f.agentCall(t, ag, at, "GET", "/agent/v1/files/"+f.fileB, nil) // deny: not in grant
	do(t, "GET", f.srv.URL+"/agent/v1/files", "", nil)             // deny: no token

	var log []AuditEntry
	json.NewDecoder(do(t, "GET", f.srv.URL+"/api/audit", f.alice, nil).Body).Decode(&log)
	find := func(action, decision, file string) *AuditEntry {
		for i := range log {
			e := &log[i]
			if e.Action == action && e.Decision == decision && e.FileID == file {
				return e
			}
		}
		return nil
	}
	if e := find("grant_create", "allow", ""); e == nil || e.GrantID != g.ID {
		t.Error("grant creation not audited")
	}
	if e := find("token_exchange", "allow", ""); e == nil || e.Actor != ag.id || e.OnBehalfOf != "alice" {
		t.Errorf("token exchange not audited correctly: %+v", e)
	}
	if e := find("download", "allow", f.fileA); e == nil || e.Actor != ag.id || e.OnBehalfOf != "alice" || e.RequestID == "" {
		t.Errorf("allowed download not audited correctly: %+v", e)
	}
	if e := find("download", "deny", f.fileB); e == nil || e.Reason != "file not in grant" {
		t.Errorf("denied download not audited correctly: %+v", e)
	}
	// The unauthenticated request is recorded too, with actor "unknown" (it can't be
	// shown to alice, since nothing verified says it was for her).
	var n int
	f.store.db.QueryRow(`SELECT COUNT(*) FROM audit WHERE actor = 'unknown' AND decision = 'deny'`).Scan(&n)
	if n != 1 {
		t.Errorf("unauthenticated request audit rows: %d, want 1", n)
	}
	// eve sees none of alice's audit entries.
	var evelog []AuditEntry
	json.NewDecoder(do(t, "GET", f.srv.URL+"/api/audit", f.eve, nil).Body).Decode(&evelog)
	if len(evelog) != 0 {
		t.Errorf("eve sees %d audit entries", len(evelog))
	}
}

func TestRequestIDEchoed(t *testing.T) {
	f := newGrantFixture(t)
	r := do(t, "GET", f.srv.URL+"/api/agents/x/keys", "", nil)
	if len(r.Header.Get("X-Request-ID")) < 8 {
		t.Error("no request id header")
	}
}
