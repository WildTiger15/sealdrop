package main

// store.go: everything the server persists, in SQLite.
//
// Zero knowledge by construction: the only columns are usernames, passkey
// credentials (public keys), user public keys, the user's *wrapped* (encrypted)
// private keys, and sealed file blobs. There is no column that could hold a
// plaintext file or an unwrapped private key, because the server never has one.

import (
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	_ "modernc.org/sqlite" // pure Go SQLite driver: no C compiler needed
)

const schema = `
CREATE TABLE IF NOT EXISTS users (
	id           BLOB PRIMARY KEY,      -- random 32 byte WebAuthn user handle
	username     TEXT UNIQUE NOT NULL,
	kem_pk       BLOB,                  -- X-Wing public key (1216 bytes)
	sig_vk       BLOB,                  -- ML-DSA-65 public key (1952 bytes)
	wrapped_keys BLOB                   -- private keys, encrypted client side
);
CREATE TABLE IF NOT EXISTS credentials (
	id      BLOB PRIMARY KEY,
	user_id BLOB NOT NULL REFERENCES users(id),
	data    TEXT NOT NULL               -- webauthn.Credential as JSON (public key, counters)
);
CREATE TABLE IF NOT EXISTS files (
	id         TEXT PRIMARY KEY,
	sender     TEXT NOT NULL,
	recipient  TEXT NOT NULL,
	blob       BLOB NOT NULL,           -- sealed file: header || ciphertext || signature
	created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
	token_hash BLOB PRIMARY KEY,        -- SHA-256 of the cookie value, not the cookie itself
	user_id    BLOB NOT NULL,
	expires_at INTEGER NOT NULL
);
`

var errNotFound = errors.New("not found")

type Store struct{ db *sql.DB }

func OpenStore(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // SQLite: one writer; keeps things simple and correct
	for _, ddl := range []string{schema, agentSchema} {
		if _, err := db.Exec(ddl); err != nil {
			return nil, err
		}
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

// User implements webauthn.User.
type User struct {
	ID          []byte
	Username    string
	KemPK       []byte
	SigVK       []byte
	WrappedKeys []byte
	Credentials []webauthn.Credential
}

func (u *User) WebAuthnID() []byte                         { return u.ID }
func (u *User) WebAuthnName() string                       { return u.Username }
func (u *User) WebAuthnDisplayName() string                { return u.Username }
func (u *User) WebAuthnCredentials() []webauthn.Credential { return u.Credentials }

func (s *Store) CreateUser(u *User, cred *webauthn.Credential) error {
	data, err := json.Marshal(cred)
	if err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT INTO users (id, username) VALUES (?, ?)`, u.ID, u.Username); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO credentials (id, user_id, data) VALUES (?, ?, ?)`, cred.ID, u.ID, string(data)); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) UsernameTaken(username string) (bool, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM users WHERE username = ?`, username).Scan(&n)
	return n > 0, err
}

func (s *Store) userWhere(clause string, arg any) (*User, error) {
	u := &User{}
	err := s.db.QueryRow(`SELECT id, username, kem_pk, sig_vk, wrapped_keys FROM users WHERE `+clause, arg).
		Scan(&u.ID, &u.Username, &u.KemPK, &u.SigVK, &u.WrappedKeys)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errNotFound
	}
	if err != nil {
		return nil, err
	}
	rows, err := s.db.Query(`SELECT data FROM credentials WHERE user_id = ?`, u.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var c webauthn.Credential
		if err := json.Unmarshal([]byte(data), &c); err != nil {
			return nil, err
		}
		u.Credentials = append(u.Credentials, c)
	}
	return u, rows.Err()
}

func (s *Store) UserByName(username string) (*User, error) {
	return s.userWhere("username = ?", username)
}
func (s *Store) UserByID(id []byte) (*User, error) { return s.userWhere("id = ?", id) }

// UpdateCredential saves the new sign counter / flags after a login.
func (s *Store) UpdateCredential(cred *webauthn.Credential) error {
	data, err := json.Marshal(cred)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`UPDATE credentials SET data = ? WHERE id = ?`, string(data), cred.ID)
	return err
}

// SetKeys stores a user's public keys and wrapped private keys. Only allowed
// once: an attacker who steals a session cookie must not be able to replace
// the victim's public keys with their own.
func (s *Store) SetKeys(userID, kemPK, sigVK, wrapped []byte) error {
	res, err := s.db.Exec(`UPDATE users SET kem_pk = ?, sig_vk = ?, wrapped_keys = ? WHERE id = ? AND kem_pk IS NULL`,
		kemPK, sigVK, wrapped, userID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return errors.New("keys already set")
	}
	return nil
}

type FileMeta struct {
	ID        string `json:"id"`
	Sender    string `json:"sender"`
	Recipient string `json:"recipient"`
	Size      int    `json:"size"`
	CreatedAt int64  `json:"created_at"`
}

func (s *Store) PutFile(id, sender, recipient string, blob []byte) error {
	_, err := s.db.Exec(`INSERT INTO files (id, sender, recipient, blob, created_at) VALUES (?, ?, ?, ?, ?)`,
		id, sender, recipient, blob, time.Now().Unix())
	return err
}

func (s *Store) ListFiles(username string) ([]FileMeta, error) {
	rows, err := s.db.Query(`SELECT id, sender, recipient, length(blob), created_at FROM files
		WHERE recipient = ? OR sender = ? ORDER BY created_at DESC`, username, username)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []FileMeta{}
	for rows.Next() {
		var f FileMeta
		if err := rows.Scan(&f.ID, &f.Sender, &f.Recipient, &f.Size, &f.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// GetFile returns the blob only if `username` is its sender or recipient.
func (s *Store) GetFile(id, username string) ([]byte, error) {
	var blob []byte
	err := s.db.QueryRow(`SELECT blob FROM files WHERE id = ? AND (recipient = ? OR sender = ?)`, id, username, username).Scan(&blob)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errNotFound
	}
	return blob, err
}

func (s *Store) CreateSession(tokenHash, userID []byte, expires time.Time) error {
	_, err := s.db.Exec(`INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)`, tokenHash, userID, expires.Unix())
	return err
}

func (s *Store) SessionUser(tokenHash []byte) (*User, error) {
	var userID []byte
	err := s.db.QueryRow(`SELECT user_id FROM sessions WHERE token_hash = ? AND expires_at > ?`, tokenHash, time.Now().Unix()).Scan(&userID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errNotFound
	}
	if err != nil {
		return nil, err
	}
	return s.UserByID(userID)
}

func (s *Store) DeleteSession(tokenHash []byte) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE token_hash = ?`, tokenHash)
	return err
}
