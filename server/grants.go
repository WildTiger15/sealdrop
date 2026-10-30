package main

// grants.go: a user delegates *specific* files and *specific* actions to an
// agent, until an expiry. Anything not written in a grant is denied.

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"
)

const grantSchema = `
CREATE TABLE IF NOT EXISTS grants (
	id         TEXT PRIMARY KEY,        -- "grt_" + random
	username   TEXT NOT NULL,           -- the user who delegates (acted for)
	agent_id   TEXT NOT NULL REFERENCES agents(id),
	actions    TEXT NOT NULL,           -- comma separated subset of list,download,upload,share
	share_with TEXT NOT NULL DEFAULT '',-- comma separated usernames the agent may share to
	expires_at INTEGER NOT NULL,
	revoked_at INTEGER,                 -- NULL while active
	created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS grant_files (
	grant_id    TEXT NOT NULL REFERENCES grants(id),
	file_id     TEXT NOT NULL,
	wrapped_key BLOB,                   -- file key wrapped to the agent's X-Wing key (step 5)
	PRIMARY KEY (grant_id, file_id)
);
`

// The only actions an agent can ever be given.
var allActions = []string{"list", "download", "upload", "share"}

const (
	agentKeyLen   = 4 + 1 + 1120 + 24 + 32 + 16 // SDAK blob from core/src/delegate.rs
	maxGrantTTL   = 24 * time.Hour
	maxGrantFiles = 100
	maxShareWith  = 10
)

type Grant struct {
	ID        string   `json:"id"`
	Username  string   `json:"username"`
	AgentID   string   `json:"agent_id"`
	Actions   []string `json:"actions"`
	ShareWith []string `json:"share_with"`
	FileIDs   []string `json:"file_ids"`
	ExpiresAt int64    `json:"expires_at"`
	RevokedAt *int64   `json:"revoked_at"`
	CreatedAt int64    `json:"created_at"`
}

func splitList(s string) []string {
	if s == "" {
		return []string{}
	}
	return strings.Split(s, ",")
}

func (s *Store) CreateGrant(g *Grant, wrapped map[string][]byte) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT INTO grants (id, username, agent_id, actions, share_with, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, g.ID, g.Username, g.AgentID, strings.Join(g.Actions, ","),
		strings.Join(g.ShareWith, ","), g.ExpiresAt, g.CreatedAt); err != nil {
		return err
	}
	for _, f := range g.FileIDs {
		if _, err := tx.Exec(`INSERT INTO grant_files (grant_id, file_id, wrapped_key) VALUES (?, ?, ?)`, g.ID, f, wrapped[f]); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) scanGrant(row interface{ Scan(...any) error }) (*Grant, error) {
	g := &Grant{}
	var actions, share string
	var revoked sql.NullInt64
	if err := row.Scan(&g.ID, &g.Username, &g.AgentID, &actions, &share, &g.ExpiresAt, &revoked, &g.CreatedAt); err != nil {
		return nil, err
	}
	g.Actions, g.ShareWith = splitList(actions), splitList(share)
	if revoked.Valid {
		g.RevokedAt = &revoked.Int64
	}
	rows, err := s.db.Query(`SELECT file_id FROM grant_files WHERE grant_id = ? ORDER BY file_id`, g.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	g.FileIDs = []string{}
	for rows.Next() {
		var f string
		if err := rows.Scan(&f); err != nil {
			return nil, err
		}
		g.FileIDs = append(g.FileIDs, f)
	}
	return g, rows.Err()
}

const grantCols = `id, username, agent_id, actions, share_with, expires_at, revoked_at, created_at`

func (s *Store) GrantByID(id string) (*Grant, error) {
	g, err := s.scanGrant(s.db.QueryRow(`SELECT `+grantCols+` FROM grants WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errNotFound
	}
	return g, err
}

func (s *Store) GrantsOf(username string) ([]*Grant, error) {
	rows, err := s.db.Query(`SELECT id FROM grants WHERE username = ? ORDER BY created_at DESC`, username)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	out := []*Grant{}
	for _, id := range ids {
		g, err := s.GrantByID(id)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, nil
}

// RevokeGrant ends a grant now and deletes every file key wrapped to the agent
// under it, in one transaction. Only the user who made the grant may revoke it.
func (s *Store) RevokeGrant(id, username string, now time.Time) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.Exec(`UPDATE grants SET revoked_at = COALESCE(revoked_at, ?) WHERE id = ? AND username = ?`, now.Unix(), id, username)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return errNotFound
	}
	if _, err := tx.Exec(`UPDATE grant_files SET wrapped_key = NULL WHERE grant_id = ?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

// WrappedKeysLeft counts wrapped keys still stored for a grant (0 after revocation).
func (s *Store) WrappedKeysLeft(grantID string) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM grant_files WHERE grant_id = ? AND wrapped_key IS NOT NULL`, grantID).Scan(&n)
	return n, err
}

// AgentFileKey returns a granted file's sender and the file key wrapped to the agent.
func (s *Store) AgentFileKey(grantID, fileID string) (sender string, wrapped []byte, err error) {
	err = s.db.QueryRow(`SELECT f.sender, g.wrapped_key FROM grant_files g JOIN files f ON f.id = g.file_id
		WHERE g.grant_id = ? AND g.file_id = ?`, grantID, fileID).Scan(&sender, &wrapped)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil, errNotFound
	}
	return sender, wrapped, err
}

// PutAgentFile stores a file an agent sealed. The sender is "agent:<id>"
// (usernames can't contain ':'), and on_behalf_of names the delegating user.
func (s *Store) PutAgentFile(id, agentID, recipient, onBehalfOf string, blob []byte) error {
	_, err := s.db.Exec(`INSERT INTO files (id, sender, recipient, blob, created_at, on_behalf_of) VALUES (?, ?, ?, ?, ?, ?)`,
		id, "agent:"+agentID, recipient, blob, time.Now().Unix(), onBehalfOf)
	return err
}

// FileRecipient returns who a file was sent to (used to check a user may delegate it).
func (s *Store) FileRecipient(id string) (string, error) {
	var r string
	err := s.db.QueryRow(`SELECT recipient FROM files WHERE id = ?`, id).Scan(&r)
	if errors.Is(err, sql.ErrNoRows) {
		return "", errNotFound
	}
	return r, err
}

type grantFileReq struct {
	FileID     string `json:"file_id"`
	WrappedKey []byte `json:"wrapped_key"` // base64 in JSON
}

type grantReq struct {
	AgentID    string         `json:"agent_id"`
	Actions    []string       `json:"actions"`
	Files      []grantFileReq `json:"files"`
	ShareWith  []string       `json:"share_with"`
	TTLMinutes int            `json:"ttl_minutes"`
}

// validateGrant turns a request into a Grant, or says why not. Deny by default:
// unknown actions, files the user can't read, and unknown users are refused.
func (a *API) validateGrant(u *User, req *grantReq, now time.Time) (*Grant, map[string][]byte, string) {
	if _, err := a.store.AgentByID(req.AgentID); err != nil {
		return nil, nil, "no such agent"
	}
	if len(req.Actions) == 0 {
		return nil, nil, "choose at least one action"
	}
	actions := []string{}
	for _, act := range req.Actions {
		if !slices.Contains(allActions, act) {
			return nil, nil, "unknown action " + act
		}
		if !slices.Contains(actions, act) {
			actions = append(actions, act)
		}
	}
	ttl := time.Duration(req.TTLMinutes) * time.Minute
	if ttl <= 0 || ttl > maxGrantTTL {
		return nil, nil, "expiry must be between 1 minute and 24 hours"
	}
	if len(req.Files) > maxGrantFiles || len(req.ShareWith) > maxShareWith {
		return nil, nil, "too many files or share recipients"
	}
	files, wrapped := []string{}, map[string][]byte{}
	for _, f := range req.Files {
		rcpt, err := a.store.FileRecipient(f.FileID)
		if err != nil || rcpt != u.Username {
			// You can only delegate files you can decrypt: ones sent to you.
			return nil, nil, "you can only grant files that were sent to you"
		}
		if _, dup := wrapped[f.FileID]; dup {
			continue
		}
		files = append(files, f.FileID)
		wrapped[f.FileID] = f.WrappedKey
	}
	// Step 5: an agent can only read a file if the user's client wrapped that
	// file's key to the agent. The server checks the shape; it can't open it.
	if slices.Contains(actions, "download") || slices.Contains(actions, "share") {
		for _, f := range files {
			if k := wrapped[f]; len(k) != agentKeyLen || !bytes.HasPrefix(k, []byte("SDAK")) {
				return nil, nil, "download and share need the file key wrapped to the agent for every file"
			}
		}
	} else {
		wrapped = map[string][]byte{} // list/upload only: store no keys at all
	}
	share := []string{}
	for _, name := range req.ShareWith {
		if other, err := a.store.UserByName(name); err != nil || other.KemPK == nil || name == u.Username {
			return nil, nil, "unknown share recipient " + name
		}
		share = append(share, name)
	}
	if slices.Contains(actions, "share") && len(share) == 0 {
		return nil, nil, "the share action needs at least one allowed recipient"
	}
	return &Grant{
		ID: "grt_" + randomToken()[:24], Username: u.Username, AgentID: req.AgentID,
		Actions: actions, ShareWith: share, FileIDs: files,
		ExpiresAt: now.Add(ttl).Unix(), CreatedAt: now.Unix(),
	}, wrapped, ""
}

// POST /api/grants
func (a *API) CreateGrant(w http.ResponseWriter, r *http.Request, u *User) {
	var req grantReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, "bad request")
		return
	}
	g, wrapped, why := a.validateGrant(u, &req, time.Now())
	if g == nil {
		httpError(w, http.StatusBadRequest, why)
		return
	}
	if err := a.store.CreateGrant(g, wrapped); err != nil {
		httpError(w, http.StatusInternalServerError, "could not create grant")
		return
	}
	// The grant token is the RFC 8693 subject token the agent will exchange.
	// It is useless on its own: exchanging it also needs the agent's private key.
	tok, err := a.issuer.MintGrantToken(g)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "could not sign grant token")
		return
	}
	writeJSON(w, map[string]any{"grant": g, "grant_token": tok})
}

// DELETE /api/grants/{id}
func (a *API) RevokeGrant(w http.ResponseWriter, r *http.Request, u *User) {
	if err := a.store.RevokeGrant(r.PathValue("id"), u.Username, a.issuer.now()); err != nil {
		httpError(w, http.StatusNotFound, "no such grant")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// GET /api/grants
func (a *API) ListGrants(w http.ResponseWriter, r *http.Request, u *User) {
	gs, err := a.store.GrantsOf(u.Username)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "could not list grants")
		return
	}
	writeJSON(w, gs)
}
