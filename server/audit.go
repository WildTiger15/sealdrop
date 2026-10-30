package main

// audit.go: an append-only record of every agent request, token exchange and
// grant change: which agent acted, for which user, what it tried, on which
// file, and what was decided and why.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"regexp"
	"time"
)

const auditSchema = `
CREATE TABLE IF NOT EXISTS audit (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	ts_ms        INTEGER NOT NULL,
	request_id   TEXT NOT NULL,
	actor        TEXT NOT NULL,   -- agent id (or username for grant changes); "unknown" if unauthenticated
	on_behalf_of TEXT NOT NULL,   -- the user the actor acted for ("" if unknown)
	action       TEXT NOT NULL,   -- list | download | upload | share | token_exchange | grant_create | grant_revoke
	file_id      TEXT NOT NULL,
	grant_id     TEXT NOT NULL,
	decision     TEXT NOT NULL,   -- allow | deny
	reason       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_user ON audit(on_behalf_of, id);
CREATE INDEX IF NOT EXISTS audit_actor ON audit(actor, id);
`

type AuditEntry struct {
	ID         int64  `json:"id"`
	TimeMS     int64  `json:"ts_ms"`
	RequestID  string `json:"request_id"`
	Actor      string `json:"actor"`
	OnBehalfOf string `json:"on_behalf_of"`
	Action     string `json:"action"`
	FileID     string `json:"file_id"`
	GrantID    string `json:"grant_id"`
	Decision   string `json:"decision"`
	Reason     string `json:"reason"`
}

func (s *Store) Audit(e AuditEntry) error {
	_, err := s.db.Exec(`INSERT INTO audit (ts_ms, request_id, actor, on_behalf_of, action, file_id, grant_id, decision, reason)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		time.Now().UnixMilli(), e.RequestID, e.Actor, e.OnBehalfOf, e.Action, e.FileID, e.GrantID, e.Decision, e.Reason)
	return err
}

// AuditFor returns entries where the user was acted for, or acted themselves.
func (s *Store) AuditFor(username string, limit int) ([]AuditEntry, error) {
	rows, err := s.db.Query(`SELECT id, ts_ms, request_id, actor, on_behalf_of, action, file_id, grant_id, decision, reason
		FROM audit WHERE on_behalf_of = ? OR actor = ? ORDER BY id DESC LIMIT ?`, username, username, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AuditEntry{}
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.TimeMS, &e.RequestID, &e.Actor, &e.OnBehalfOf, &e.Action, &e.FileID, &e.GrantID, &e.Decision, &e.Reason); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ---- request ids ----

type ctxKey int

const requestIDKey ctxKey = 0

var requestIDRe = regexp.MustCompile(`^[A-Za-z0-9_-]{8,64}$`)

// withRequestID gives every request an id (a well-formed incoming X-Request-ID
// is kept, so a client's logs can be matched to ours) and echoes it back.
func withRequestID(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if !requestIDRe.MatchString(id) {
			b := make([]byte, 12)
			rand.Read(b)
			id = hex.EncodeToString(b)
		}
		w.Header().Set("X-Request-ID", id)
		h.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDKey, id)))
	})
}

func requestID(r *http.Request) string {
	id, _ := r.Context().Value(requestIDKey).(string)
	return id
}

func decisionWord(allow bool) string {
	if allow {
		return "allow"
	}
	return "deny"
}

// GET /api/audit
func (a *API) AuditLog(w http.ResponseWriter, r *http.Request, u *User) {
	entries, err := a.store.AuditFor(u.Username, 500)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "could not read audit log")
		return
	}
	writeJSON(w, entries)
}
