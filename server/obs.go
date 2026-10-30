package main

// obs.go: observability. Structured JSON logs with request ids, Prometheus
// metrics (requests, latency, policy decisions and denials, policy check
// time), and a health endpoint. Logs and metrics never contain request
// bodies, tokens, keys or file contents.

import (
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	httpRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sealdrop_http_requests_total", Help: "HTTP requests by route pattern, method and status code.",
	}, []string{"route", "method", "code"})
	httpLatency = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name: "sealdrop_http_request_duration_seconds", Help: "HTTP request latency by route pattern.",
		Buckets: prometheus.ExponentialBuckets(0.0005, 2, 16),
	}, []string{"route"})
	policyDecisions = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sealdrop_policy_decisions_total", Help: "Agent policy decisions by action and decision.",
	}, []string{"action", "decision"})
	policyDenials = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sealdrop_policy_denials_total", Help: "Agent policy denials by reason category.",
	}, []string{"reason"})
	policyLatency = promauto.NewHistogram(prometheus.HistogramOpts{
		Name: "sealdrop_policy_check_duration_seconds", Help: "Time spent inside Decide().",
		Buckets: prometheus.ExponentialBuckets(1e-7, 2, 16), // 100 ns .. 3.3 ms
	})
	tokenExchanges = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sealdrop_token_exchanges_total", Help: "OAuth token exchanges by result (issued or the OAuth error code).",
	}, []string{"result"})
)

// setupLogging switches the process to JSON logs on stderr. Existing log.Printf
// calls are routed through slog too.
func setupLogging() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))
}

// reasonCategory keeps metric label values few and fixed: "authentication
// failed: DPoP proof replayed" becomes "authentication failed".
func reasonCategory(reason string) string {
	if i := strings.Index(reason, ":"); i > 0 {
		reason = reason[:i]
	}
	if strings.HasPrefix(reason, "allowed by grant") {
		return "allowed"
	}
	return reason
}

func observePolicy(action string, d Decision, took time.Duration) {
	policyLatency.Observe(took.Seconds())
	policyDecisions.WithLabelValues(action, decisionWord(d.Allow)).Inc()
	if !d.Allow {
		policyDenials.WithLabelValues(reasonCategory(d.Reason)).Inc()
	}
}

type statusRecorder struct {
	http.ResponseWriter
	code int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.code = code
	s.ResponseWriter.WriteHeader(code)
}

// observe logs one JSON line per request and records request metrics.
// It runs inside withRequestID, so the id is available.
func observe(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, code: http.StatusOK}
		h.ServeHTTP(rec, r)
		took := time.Since(start)
		route := r.Pattern // set by ServeMux, e.g. "GET /agent/v1/files/{id}" (never raw ids)
		if route == "" {
			route = "unmatched"
		}
		httpRequests.WithLabelValues(route, r.Method, strconv.Itoa(rec.code)).Inc()
		httpLatency.WithLabelValues(route).Observe(took.Seconds())
		if route == "GET /healthz" || route == "GET /metrics" {
			return // don't flood logs with probes
		}
		slog.Info("request", "request_id", requestID(r), "method", r.Method, "route", route,
			"status", rec.code, "duration_ms", float64(took.Microseconds())/1000)
	})
}

// GET /healthz
func (a *API) Health(w http.ResponseWriter, r *http.Request) {
	if err := a.store.db.PingContext(r.Context()); err != nil {
		httpError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}
	writeJSON(w, map[string]string{"status": "ok"})
}

func metricsHandler() http.Handler { return promhttp.Handler() }
