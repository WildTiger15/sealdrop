package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

// testServer builds the real router with a temp database. Passkey ceremonies
// need a browser, so users are created directly and given a session cookie.
var testIssuers = map[string]*Issuer{}

func testServer(t *testing.T) (*httptest.Server, *Store, *Auth) {
	t.Helper()
	store, err := OpenStore(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	wa, err := webauthn.New(&webauthn.Config{RPDisplayName: "t", RPID: "localhost", RPOrigins: []string{"http://localhost"}})
	if err != nil {
		t.Fatal(err)
	}
	auth := &Auth{wa: wa, store: store, ceremonies: map[string]*ceremony{}}
	issuer, err := LoadOrCreateIssuer(store, "placeholder", filepath.Join(t.TempDir(), "token_key"))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(securityHeaders(routes(auth, &API{auth: auth, store: store, issuer: issuer}, t.TempDir())))
	issuer.origin = srv.URL // tokens name the test server as issuer
	testIssuers[srv.URL] = issuer
	t.Cleanup(srv.Close)
	return srv, store, auth
}

func makeUser(t *testing.T, store *Store, name string) string {
	t.Helper()
	u := &User{ID: []byte("id-" + name), Username: name}
	if err := store.CreateUser(u, &webauthn.Credential{ID: []byte("cred-" + name)}); err != nil {
		t.Fatal(err)
	}
	tok := randomToken()
	if err := store.CreateSession(hashToken(tok), u.ID, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	return tok
}

func do(t *testing.T, method, url, token string, body any) *http.Response {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		json.NewEncoder(&buf).Encode(body)
	}
	req, _ := http.NewRequest(method, url, &buf)
	if token != "" {
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func validKeys() keysReq {
	return keysReq{
		KemPK:       bytes.Repeat([]byte{1}, kemPKLen),
		SigVK:       bytes.Repeat([]byte{2}, sigVKLen),
		WrappedKeys: append([]byte("SDKW"), bytes.Repeat([]byte{3}, wrappedLen-4)...),
	}
}

func fakeSealed() []byte {
	return append([]byte("SDRP"), bytes.Repeat([]byte{9}, minSealedLen)...)
}

func TestRequiresSignIn(t *testing.T) {
	srv, _, _ := testServer(t)
	for _, p := range []struct{ m, path string }{{"GET", "/api/me"}, {"PUT", "/api/me/keys"}, {"POST", "/api/files"}, {"GET", "/api/files"}, {"GET", "/api/files/x"}} {
		if r := do(t, p.m, srv.URL+p.path, "", nil); r.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s %s: got %d, want 401", p.m, p.path, r.StatusCode)
		}
		if r := do(t, p.m, srv.URL+p.path, "forged-token", nil); r.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s %s with forged cookie: got %d, want 401", p.m, p.path, r.StatusCode)
		}
	}
}

func TestKeysFlow(t *testing.T) {
	srv, store, _ := testServer(t)
	alice := makeUser(t, store, "alice")

	bad := validKeys()
	bad.KemPK = bad.KemPK[:100]
	if r := do(t, "PUT", srv.URL+"/api/me/keys", alice, bad); r.StatusCode != http.StatusBadRequest {
		t.Errorf("short kem key: got %d, want 400", r.StatusCode)
	}
	if r := do(t, "PUT", srv.URL+"/api/me/keys", alice, validKeys()); r.StatusCode != http.StatusNoContent {
		t.Fatalf("set keys: got %d", r.StatusCode)
	}
	// Second attempt (e.g. a stolen session trying to swap keys) is refused.
	if r := do(t, "PUT", srv.URL+"/api/me/keys", alice, validKeys()); r.StatusCode != http.StatusConflict {
		t.Errorf("replace keys: got %d, want 409", r.StatusCode)
	}
	r := do(t, "GET", srv.URL+"/api/users/alice/keys", "", nil)
	var got map[string]string
	json.NewDecoder(r.Body).Decode(&got)
	if r.StatusCode != 200 || got["kem_pk"] == "" || got["sig_vk"] == "" {
		t.Errorf("public keys: %d %v", r.StatusCode, got)
	}
	if _, leaked := got["wrapped_keys"]; leaked {
		t.Error("public key endpoint must not return wrapped private keys")
	}
}

func TestFileAccessControl(t *testing.T) {
	srv, store, _ := testServer(t)
	alice := makeUser(t, store, "alice")
	bob := makeUser(t, store, "bob")
	eve := makeUser(t, store, "eve")
	do(t, "PUT", srv.URL+"/api/me/keys", bob, validKeys())

	if r := do(t, "POST", srv.URL+"/api/files", alice, uploadReq{Recipient: "bob", Blob: []byte("plaintext!")}); r.StatusCode != 400 {
		t.Errorf("non-sealed upload: got %d, want 400", r.StatusCode)
	}
	if r := do(t, "POST", srv.URL+"/api/files", alice, uploadReq{Recipient: "nobody", Blob: fakeSealed()}); r.StatusCode != 404 {
		t.Errorf("unknown recipient: got %d, want 404", r.StatusCode)
	}
	r := do(t, "POST", srv.URL+"/api/files", alice, uploadReq{Recipient: "bob", Blob: fakeSealed()})
	var up map[string]string
	json.NewDecoder(r.Body).Decode(&up)
	if r.StatusCode != 200 || up["id"] == "" {
		t.Fatalf("upload: %d", r.StatusCode)
	}

	for who, tok := range map[string]string{"bob": bob, "alice": alice} {
		if r := do(t, "GET", srv.URL+"/api/files/"+up["id"], tok, nil); r.StatusCode != 200 {
			t.Errorf("%s download: got %d, want 200", who, r.StatusCode)
		}
	}
	if r := do(t, "GET", srv.URL+"/api/files/"+up["id"], eve, nil); r.StatusCode != 404 {
		t.Errorf("eve download: got %d, want 404", r.StatusCode)
	}
	var list []FileMeta
	json.NewDecoder(do(t, "GET", srv.URL+"/api/files", eve, nil).Body).Decode(&list)
	if len(list) != 0 {
		t.Errorf("eve sees %d files, want 0", len(list))
	}
}

func TestUsernameValidation(t *testing.T) {
	srv, store, _ := testServer(t)
	makeUser(t, store, "taken")
	for _, name := range []string{"", "ab", "Has Space", "UPPER", "../etc", "x'; DROP TABLE users;--"} {
		if r := do(t, "POST", srv.URL+"/api/register/begin", "", usernameReq{name}); r.StatusCode != 400 {
			t.Errorf("username %q: got %d, want 400", name, r.StatusCode)
		}
	}
	if r := do(t, "POST", srv.URL+"/api/register/begin", "", usernameReq{"taken"}); r.StatusCode != 409 {
		t.Errorf("taken username: got %d, want 409", r.StatusCode)
	}
	if r := do(t, "POST", srv.URL+"/api/register/begin", "", usernameReq{"newuser"}); r.StatusCode != 200 {
		t.Errorf("valid username: got %d, want 200", r.StatusCode)
	}
}

func TestSecurityHeaders(t *testing.T) {
	srv, _, _ := testServer(t)
	r := do(t, "GET", srv.URL+"/", "", nil)
	if csp := r.Header.Get("Content-Security-Policy"); csp == "" {
		t.Error("missing CSP header")
	}
}
