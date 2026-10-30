package main

// auth.go: passkey registration and sign in (go-webauthn), plus sessions.
//
// The server asks the browser for the WebAuthn PRF extension with a fixed
// salt. The PRF *output* never reaches the server: the browser keeps it and
// uses it (through HKDF, in Rust/WASM) to unwrap the user's private keys.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"regexp"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

const (
	sessionCookie  = "sd_session"
	ceremonyCookie = "sd_ceremony"
	sessionTTL     = 12 * time.Hour
	ceremonyTTL    = 5 * time.Minute
)

// prfSalt is public and the same for everyone; PRF output is still unique per
// passkey because the authenticator mixes in its own per-credential secret.
var prfSalt = func() []byte { h := sha256.Sum256([]byte("SealDrop PRF salt v1")); return h[:] }()

var usernameRe = regexp.MustCompile(`^[a-z0-9_]{3,32}$`)

// ceremony is the state kept between a /begin and its /finish call.
type ceremony struct {
	session  webauthn.SessionData
	username string
	userID   []byte
	expires  time.Time
}

type Auth struct {
	wa    *webauthn.WebAuthn
	store *Store
	https bool

	mu         sync.Mutex
	ceremonies map[string]*ceremony
}

func randomToken() string {
	b := make([]byte, 32)
	rand.Read(b) // crypto/rand.Read never returns an error on supported platforms (Go >= 1.24)
	return hex.EncodeToString(b)
}

func hashToken(t string) []byte {
	h := sha256.Sum256([]byte(t))
	return h[:]
}

func (a *Auth) putCeremony(w http.ResponseWriter, c *ceremony) {
	id := randomToken()
	c.expires = time.Now().Add(ceremonyTTL)
	a.mu.Lock()
	for k, v := range a.ceremonies { // drop stale ones
		if time.Now().After(v.expires) {
			delete(a.ceremonies, k)
		}
	}
	a.ceremonies[id] = c
	a.mu.Unlock()
	http.SetCookie(w, a.cookie(ceremonyCookie, id, ceremonyTTL))
}

// takeCeremony returns the ceremony once; a challenge can never be reused.
func (a *Auth) takeCeremony(r *http.Request) *ceremony {
	ck, err := r.Cookie(ceremonyCookie)
	if err != nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	c := a.ceremonies[ck.Value]
	delete(a.ceremonies, ck.Value)
	if c == nil || time.Now().After(c.expires) {
		return nil
	}
	return c
}

func (a *Auth) cookie(name, value string, ttl time.Duration) *http.Cookie {
	return &http.Cookie{
		Name: name, Value: value, Path: "/", MaxAge: int(ttl.Seconds()),
		HttpOnly: true, Secure: a.https, SameSite: http.SameSiteStrictMode,
	}
}

func (a *Auth) startSession(w http.ResponseWriter, userID []byte) error {
	tok := randomToken()
	if err := a.store.CreateSession(hashToken(tok), userID, time.Now().Add(sessionTTL)); err != nil {
		return err
	}
	http.SetCookie(w, a.cookie(sessionCookie, tok, sessionTTL))
	return nil
}

// CurrentUser returns the signed in user, or nil.
func (a *Auth) CurrentUser(r *http.Request) *User {
	ck, err := r.Cookie(sessionCookie)
	if err != nil {
		return nil
	}
	u, err := a.store.SessionUser(hashToken(ck.Value))
	if err != nil {
		return nil
	}
	return u
}

type usernameReq struct {
	Username string `json:"username"`
}

func readUsername(r *http.Request) (string, bool) {
	var req usernameReq
	if err := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1024)).Decode(&req); err != nil {
		return "", false
	}
	return req.Username, usernameRe.MatchString(req.Username)
}

func (a *Auth) RegisterBegin(w http.ResponseWriter, r *http.Request) {
	username, ok := readUsername(r)
	if !ok {
		httpError(w, http.StatusBadRequest, "username must be 3-32 chars: a-z 0-9 _")
		return
	}
	if taken, err := a.store.UsernameTaken(username); err != nil || taken {
		httpError(w, http.StatusConflict, "username not available")
		return
	}
	u := &User{ID: make([]byte, 32), Username: username}
	rand.Read(u.ID)
	creation, session, err := a.wa.BeginRegistration(u,
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementPreferred),
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementPreferred,
			UserVerification: protocol.VerificationRequired,
		}),
		webauthn.WithExtensions(webauthn.WithExtensionPRFSupport()),
	)
	if err != nil {
		log.Printf("register begin: %v", err)
		httpError(w, http.StatusInternalServerError, "could not start registration")
		return
	}
	a.putCeremony(w, &ceremony{session: *session, username: username, userID: u.ID})
	writeJSON(w, creation)
}

func (a *Auth) RegisterFinish(w http.ResponseWriter, r *http.Request) {
	c := a.takeCeremony(r)
	if c == nil {
		httpError(w, http.StatusBadRequest, "registration expired, try again")
		return
	}
	u := &User{ID: c.userID, Username: c.username}
	cred, err := a.wa.FinishRegistration(u, c.session, r)
	if err != nil {
		log.Printf("register finish: %v", err)
		httpError(w, http.StatusBadRequest, "passkey registration failed")
		return
	}
	if err := a.store.CreateUser(u, cred); err != nil {
		httpError(w, http.StatusConflict, "username not available")
		return
	}
	if err := a.startSession(w, u.ID); err != nil {
		httpError(w, http.StatusInternalServerError, "could not start session")
		return
	}
	writeJSON(w, map[string]string{"username": u.Username})
}

func (a *Auth) LoginBegin(w http.ResponseWriter, r *http.Request) {
	username, ok := readUsername(r)
	if !ok {
		httpError(w, http.StatusBadRequest, "invalid username")
		return
	}
	u, err := a.store.UserByName(username)
	if err != nil {
		// Same message whether or not the user exists.
		httpError(w, http.StatusBadRequest, "sign in failed")
		return
	}
	assertion, session, err := a.wa.BeginLogin(u,
		webauthn.WithUserVerification(protocol.VerificationRequired),
		webauthn.WithAssertionExtensions(webauthn.WithExtensionPRF(protocol.PRFValues{First: prfSalt})),
	)
	if err != nil {
		log.Printf("login begin: %v", err)
		httpError(w, http.StatusInternalServerError, "could not start sign in")
		return
	}
	a.putCeremony(w, &ceremony{session: *session, username: username, userID: u.ID})
	writeJSON(w, assertion)
}

func (a *Auth) LoginFinish(w http.ResponseWriter, r *http.Request) {
	c := a.takeCeremony(r)
	if c == nil {
		httpError(w, http.StatusBadRequest, "sign in expired, try again")
		return
	}
	u, err := a.store.UserByID(c.userID)
	if err != nil {
		httpError(w, http.StatusBadRequest, "sign in failed")
		return
	}
	cred, err := a.wa.FinishLogin(u, c.session, r)
	if err != nil {
		log.Printf("login finish: %v", err)
		httpError(w, http.StatusUnauthorized, "sign in failed")
		return
	}
	if cred.Authenticator.CloneWarning {
		httpError(w, http.StatusUnauthorized, "passkey counter went backwards: possible cloned authenticator")
		return
	}
	if err := a.store.UpdateCredential(cred); err != nil {
		httpError(w, http.StatusInternalServerError, "could not save credential")
		return
	}
	if err := a.startSession(w, u.ID); err != nil {
		httpError(w, http.StatusInternalServerError, "could not start session")
		return
	}
	writeJSON(w, map[string]string{"username": u.Username})
}

func (a *Auth) Logout(w http.ResponseWriter, r *http.Request) {
	if ck, err := r.Cookie(sessionCookie); err == nil {
		a.store.DeleteSession(hashToken(ck.Value))
	}
	http.SetCookie(w, a.cookie(sessionCookie, "", -time.Second))
	w.WriteHeader(http.StatusNoContent)
}
