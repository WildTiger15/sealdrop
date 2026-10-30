package main

// agents.go: AI agents as first class identities (Milestone 7).
//
// An agent generates all of its own keys and only ever sends us the public
// halves:
//   - an X-Wing public key, so a user's browser can wrap file keys to it;
//   - an ML-DSA-65 verifying key, so files the agent uploads can be verified;
//   - an Ed25519 public key, which authenticates the agent at the OAuth token
//     endpoint (signed client assertions) and on every request (DPoP proofs).
// The agent's private keys never leave the agent, and there is no shared
// secret: nothing the server stores lets anyone act as the agent.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"time"
)

const agentSchema = `
CREATE TABLE IF NOT EXISTS agents (
	id            TEXT PRIMARY KEY,     -- "agt_" + random, the OAuth client_id
	name          TEXT NOT NULL,
	registered_by TEXT NOT NULL,        -- username of the user who registered it
	kem_pk        BLOB NOT NULL,        -- X-Wing public key (1216 bytes)
	sig_vk        BLOB NOT NULL,        -- ML-DSA-65 public key (1952 bytes)
	auth_key      BLOB NOT NULL,        -- Ed25519 public key (32 bytes)
	jkt           TEXT NOT NULL,        -- RFC 7638 thumbprint of auth_key as a JWK
	created_at    INTEGER NOT NULL
);
`

var agentNameRe = regexp.MustCompile(`^[A-Za-z0-9 _.-]{1,40}$`)

type Agent struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	RegisteredBy string `json:"registered_by"`
	KemPK        []byte `json:"-"`
	SigVK        []byte `json:"-"`
	AuthKey      []byte `json:"-"`
	JKT          string `json:"jkt"`
	CreatedAt    int64  `json:"created_at"`
}

var b64url = base64.RawURLEncoding

// jwkThumbprint is the RFC 7638 SHA-256 thumbprint of an Ed25519 public key
// as an OKP JWK. Members in lexicographic order, no whitespace (RFC 7638 §3).
func jwkThumbprint(pub ed25519.PublicKey) string {
	canonical := `{"crv":"Ed25519","kty":"OKP","x":"` + b64url.EncodeToString(pub) + `"}`
	sum := sha256.Sum256([]byte(canonical))
	return b64url.EncodeToString(sum[:])
}

func (s *Store) CreateAgent(a *Agent) error {
	_, err := s.db.Exec(`INSERT INTO agents (id, name, registered_by, kem_pk, sig_vk, auth_key, jkt, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, a.ID, a.Name, a.RegisteredBy, a.KemPK, a.SigVK, a.AuthKey, a.JKT, a.CreatedAt)
	return err
}

func (s *Store) AgentByID(id string) (*Agent, error) {
	a := &Agent{}
	err := s.db.QueryRow(`SELECT id, name, registered_by, kem_pk, sig_vk, auth_key, jkt, created_at FROM agents WHERE id = ?`, id).
		Scan(&a.ID, &a.Name, &a.RegisteredBy, &a.KemPK, &a.SigVK, &a.AuthKey, &a.JKT, &a.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errNotFound
	}
	return a, err
}

func (s *Store) AgentsRegisteredBy(username string) ([]Agent, error) {
	rows, err := s.db.Query(`SELECT id, name, registered_by, jkt, created_at FROM agents WHERE registered_by = ? ORDER BY created_at DESC`, username)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Agent{}
	for rows.Next() {
		var a Agent
		if err := rows.Scan(&a.ID, &a.Name, &a.RegisteredBy, &a.JKT, &a.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

type agentReq struct {
	Name    string `json:"name"`
	KemPK   []byte `json:"kem_pk"`   // base64 (standard) in JSON
	SigVK   []byte `json:"sig_vk"`   // base64 (standard) in JSON
	AuthKey []byte `json:"auth_key"` // base64 (standard) in JSON, 32 byte Ed25519 public key
}

// POST /api/agents  (signed in user registers an agent from its public bundle)
func (a *API) RegisterAgent(w http.ResponseWriter, r *http.Request, u *User) {
	var req agentReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, "bad request")
		return
	}
	if !agentNameRe.MatchString(req.Name) || len(req.KemPK) != kemPKLen || len(req.SigVK) != sigVKLen ||
		len(req.AuthKey) != ed25519.PublicKeySize {
		httpError(w, http.StatusBadRequest, "agent keys have the wrong size, or the name is invalid")
		return
	}
	ag := &Agent{
		ID: "agt_" + randomToken()[:24], Name: req.Name, RegisteredBy: u.Username,
		KemPK: req.KemPK, SigVK: req.SigVK, AuthKey: req.AuthKey,
		JKT: jwkThumbprint(ed25519.PublicKey(req.AuthKey)), CreatedAt: time.Now().Unix(),
	}
	if err := a.store.CreateAgent(ag); err != nil {
		httpError(w, http.StatusInternalServerError, "could not register agent")
		return
	}
	writeJSON(w, ag)
}

// GET /api/agents  (agents this user registered)
func (a *API) MyAgents(w http.ResponseWriter, r *http.Request, u *User) {
	agents, err := a.store.AgentsRegisteredBy(u.Username)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "could not list agents")
		return
	}
	writeJSON(w, agents)
}

// GET /api/agents/{id}/keys  (public, like user public keys)
func (a *API) AgentKeys(w http.ResponseWriter, r *http.Request) {
	ag, err := a.store.AgentByID(r.PathValue("id"))
	if err != nil {
		httpError(w, http.StatusNotFound, "no such agent")
		return
	}
	writeJSON(w, map[string]string{
		"id": ag.ID, "name": ag.Name, "registered_by": ag.RegisteredBy,
		"kem_pk": b64(ag.KemPK), "sig_vk": b64(ag.SigVK), "jkt": ag.JKT,
	})
}
