// SealDrop server: stores public keys, passkey credentials, wrapped
// (encrypted) private keys and sealed file blobs. It never sees plaintext.
//
//	go run . -addr :8080 -db data/sealdrop.db -static ../web/dist
package main

import (
	"flag"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

func main() {
	// Hosting platforms (e.g. Render) pass the port and public URL as env vars.
	defaultAddr, defaultOrigin := "localhost:8080", "http://localhost:8080"
	if p := os.Getenv("PORT"); p != "" {
		defaultAddr = ":" + p
	}
	if o := os.Getenv("RENDER_EXTERNAL_URL"); o != "" {
		defaultOrigin = o
	}
	addr := flag.String("addr", defaultAddr, "listen address")
	dbPath := flag.String("db", envOr("SEALDROP_DB", "data/sealdrop.db"), "SQLite database file")
	static := flag.String("static", envOr("SEALDROP_STATIC", "../web/dist"), "directory with the built web client")
	origin := flag.String("origin", envOr("SEALDROP_ORIGIN", defaultOrigin), "public origin of the site (WebAuthn RP origin)")
	flag.Parse()

	u, err := url.Parse(*origin)
	if err != nil || u.Hostname() == "" {
		log.Fatalf("bad -origin %q", *origin)
	}
	wa, err := webauthn.New(&webauthn.Config{
		RPDisplayName: "SealDrop",
		RPID:          u.Hostname(), // WebAuthn RP ID: the domain, no scheme or port
		RPOrigins:     []string{*origin},
	})
	if err != nil {
		log.Fatal(err)
	}

	if err := os.MkdirAll(filepath.Dir(*dbPath), 0o700); err != nil {
		log.Fatal(err)
	}
	store, err := OpenStore(*dbPath)
	if err != nil {
		log.Fatal(err)
	}

	issuer, err := LoadOrCreateIssuer(store, strings.TrimSuffix(*origin, "/"), filepath.Join(filepath.Dir(*dbPath), "token_signing_key"))
	if err != nil {
		log.Fatal(err)
	}
	auth := &Auth{wa: wa, store: store, https: u.Scheme == "https", ceremonies: map[string]*ceremony{}}
	api := &API{auth: auth, store: store, issuer: issuer}

	srv := &http.Server{
		Addr:              *addr,
		Handler:           withRequestID(securityHeaders(routes(auth, api, *static))),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       2 * time.Minute,
		WriteTimeout:      2 * time.Minute,
		MaxHeaderBytes:    16 << 10,
	}
	log.Printf("SealDrop listening on %s (origin %s)", *addr, *origin)
	log.Fatal(srv.ListenAndServe())
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func routes(auth *Auth, api *API, static string) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/register/begin", auth.RegisterBegin)
	mux.HandleFunc("POST /api/register/finish", auth.RegisterFinish)
	mux.HandleFunc("POST /api/login/begin", auth.LoginBegin)
	mux.HandleFunc("POST /api/login/finish", auth.LoginFinish)
	mux.HandleFunc("POST /api/logout", auth.Logout)

	mux.HandleFunc("GET /api/me", api.requireUser(api.Me))
	mux.HandleFunc("PUT /api/me/keys", api.requireUser(api.PutKeys))
	mux.HandleFunc("GET /api/users/{username}/keys", api.UserKeys)
	mux.HandleFunc("POST /api/files", api.requireUser(api.Upload))
	mux.HandleFunc("GET /api/files", api.requireUser(api.List))
	mux.HandleFunc("GET /api/files/{id}", api.requireUser(api.Download))

	// Milestone 7: agents
	mux.HandleFunc("POST /api/agents", api.requireUser(api.RegisterAgent))
	mux.HandleFunc("GET /api/agents", api.requireUser(api.MyAgents))
	mux.HandleFunc("GET /api/agents/{id}/keys", api.AgentKeys)
	mux.HandleFunc("POST /api/grants", api.requireUser(api.CreateGrant))
	mux.HandleFunc("GET /api/grants", api.requireUser(api.ListGrants))
	mux.HandleFunc("DELETE /api/grants/{id}", api.requireUser(api.RevokeGrant))
	mux.HandleFunc("GET /api/audit", api.requireUser(api.AuditLog))
	mux.HandleFunc("POST /oauth/token", api.Token)
	mux.HandleFunc("GET /agent/v1/files", api.agentRoute("list", api.AgentList))
	mux.HandleFunc("GET /agent/v1/files/{id}", api.agentRoute("download", api.AgentDownload))
	mux.HandleFunc("POST /agent/v1/files", api.agentRoute("upload", api.AgentUpload))
	mux.HandleFunc("POST /agent/v1/files/{id}/share", api.agentRoute("share", api.AgentShare))
	mux.HandleFunc("GET /.well-known/jwks.json", api.JWKS)

	mux.Handle("GET /", http.FileServer(http.Dir(static)))
	return mux
}

// securityHeaders: a strict Content Security Policy means injected scripts
// can't run, which matters because the page holds decrypted keys in memory.
// 'wasm-unsafe-eval' is required to instantiate WebAssembly.
func securityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' data:; "+
				"connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		h.ServeHTTP(w, r)
	})
}
