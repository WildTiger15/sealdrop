package main

import (
	"encoding/json"
	"io"
	"strings"
	"testing"
)

func TestHealthAndMetrics(t *testing.T) {
	f := newGrantFixture(t)
	var h map[string]string
	r := do(t, "GET", f.srv.URL+"/healthz", "", nil)
	json.NewDecoder(r.Body).Decode(&h)
	if r.StatusCode != 200 || h["status"] != "ok" {
		t.Fatalf("health: %d %v", r.StatusCode, h)
	}
	ag := f.newAgent(t, f.alice, "bot")
	_, gt := f.grantFor(t, ag.id, []string{"list", "download"}, 60)
	at := f.accessToken(t, ag, gt)
	f.agentCall(t, ag, at, "GET", "/agent/v1/files/"+f.fileB, nil) // a denial
	body, _ := io.ReadAll(do(t, "GET", f.srv.URL+"/metrics", "", nil).Body)
	m := string(body)
	for _, want := range []string{
		`sealdrop_policy_denials_total{reason="file not in grant"}`,
		`sealdrop_policy_decisions_total{action="download",decision="deny"}`,
		`sealdrop_policy_check_duration_seconds_count`,
		`sealdrop_token_exchanges_total{result="issued"}`,
		`sealdrop_http_requests_total{code="403",method="GET",route="GET /agent/v1/files/{id}"}`,
	} {
		if !strings.Contains(m, want) {
			t.Errorf("metrics missing %s", want)
		}
	}
	if strings.Contains(m, f.fileB) || strings.Contains(m, at[:20]) {
		t.Error("metrics contain a file id or token")
	}
}

func TestReasonCategoryIsBounded(t *testing.T) {
	for in, want := range map[string]string{
		"authentication failed: DPoP proof replayed": "authentication failed",
		"allowed by grant grt_123":                   "allowed",
		"file not in grant":                          "file not in grant",
	} {
		if got := reasonCategory(in); got != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
	}
}
