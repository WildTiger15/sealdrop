package main

import (
	"encoding/json"
	"os"
	"runtime"
	"sort"
	"testing"
	"time"
)

func median(xs []float64) float64 {
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	if len(s)%2 == 1 {
		return s[len(s)/2]
	}
	return (s[len(s)/2-1] + s[len(s)/2]) / 2
}

// TestPolicyTiming measures how long Decide takes. Set SEALDROP_TIMING_OUT to a
// file path to save the result (used for outputs/results.md).
//
//   - decide: 200 samples of 200,000 back-to-back Decide calls each (a single call,
//     or even 1000, is far shorter than the clock's resolution on Windows), reported
//     as the median per call,
//     for an allowed download and for a denial (worst case: every check runs).
//   - agent request: 300 real HTTP agent downloads, timed by the client from
//     sending to the full response (DPoP signing, token + proof verification,
//     grant load, Decide, audit write, file read), median.
func TestPolicyTiming(t *testing.T) {
	out := os.Getenv("SEALDROP_TIMING_OUT")
	if out == "" {
		t.Skip("set SEALDROP_TIMING_OUT to run the timing measurement")
	}
	perCall := func(in PolicyInput) (float64, float64) {
		// Each batch must span many clock ticks: Windows' clock advances in ~0.5-1 ms steps.
		const batches, per = 200, 200_000
		samples := make([]float64, batches)
		var sink bool
		for b := range batches {
			start := time.Now()
			for range per {
				sink = Decide(in).Allow != sink
			}
			samples[b] = float64(time.Since(start).Nanoseconds()) / per
		}
		sort.Float64s(samples)
		return median(samples), samples[batches*99/100]
	}
	allowMed, allowP99 := perCall(baseInput())
	denyIn := baseInput()
	denyIn.ShareTo, denyIn.Action = "mallory", "share" // passes every check up to the last one
	denyMed, denyP99 := perCall(denyIn)

	// The full gate over HTTP: token + DPoP verification + DB grant load + Decide + audit.
	f := newGrantFixture(t)
	ag := f.newAgent(t, f.alice, "bot")
	_, gt := f.grantFor(t, ag.id, []string{"list", "download"}, 60)
	at := f.accessToken(t, ag, gt)
	var total []float64
	for range 300 {
		start := time.Now()
		if code, _, _ := f.agentCall(t, ag, at, "GET", "/agent/v1/files/"+f.fileA, nil); code != 200 {
			t.Fatalf("download: %d", code)
		}
		total = append(total, float64(time.Since(start).Microseconds()))
	}

	res := map[string]any{
		"go":                           runtime.Version(),
		"cpus":                         runtime.NumCPU(),
		"decide_allow_median_ns":       allowMed,
		"decide_allow_p99_ns":          allowP99,
		"decide_deny_median_ns":        denyMed,
		"decide_deny_p99_ns":           denyP99,
		"agent_request_median_us":      median(total),
		"agent_request_samples":        len(total),
		"agent_request_includes":       "client DPoP signing, HTTP on localhost, token + DPoP verification, grant load, Decide, audit write, file read",
		"decide_batches_x_calls":       "200 x 200000",
		"decide_measured_with":         "time.Now around 200000-call batches (several ms each, far above clock resolution), median of batch means",
		"decide_inputs_allow_and_deny": "allowed download; share denied by the final check (all checks run)",
	}
	b, _ := json.MarshalIndent(res, "", " ")
	if err := os.WriteFile(out, b, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("Decide median: allow %.1f ns, deny %.1f ns; full agent request median %.0f µs", allowMed, denyMed, median(total))
}
