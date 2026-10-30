package main

// api.go: public keys and sealed file blobs. The server checks sizes and who
// may download what, but it cannot check (or read) what is inside a blob.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
)

// Sizes from the core crate (X-Wing, ML-DSA-65, key wrap blob, file header).
const (
	kemPKLen      = 1216
	sigVKLen      = 1952
	wrappedLen    = 4 + 1 + 1 + 16 + 24 + 64 + 16
	minSealedLen  = 1213 + 16 + 3309
	maxUploadSize = 64 << 20 // 64 MiB of ciphertext
)

var sealedMagic = []byte("SDRP")

type API struct {
	auth  *Auth
	store *Store
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

// httpError sends a short, generic message. Internal details go to the log only.
func httpError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// requireUser wraps a handler so it only runs for a signed in user.
func (a *API) requireUser(h func(http.ResponseWriter, *http.Request, *User)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u := a.auth.CurrentUser(r)
		if u == nil {
			httpError(w, http.StatusUnauthorized, "not signed in")
			return
		}
		h(w, r, u)
	}
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// GET /api/me
func (a *API) Me(w http.ResponseWriter, r *http.Request, u *User) {
	writeJSON(w, map[string]any{
		"username":     u.Username,
		"has_keys":     u.KemPK != nil,
		"wrapped_keys": b64(u.WrappedKeys),
	})
}

type keysReq struct {
	KemPK       []byte `json:"kem_pk"` // base64 in JSON (encoding/json does this for []byte)
	SigVK       []byte `json:"sig_vk"`
	WrappedKeys []byte `json:"wrapped_keys"`
}

// PUT /api/me/keys
func (a *API) PutKeys(w http.ResponseWriter, r *http.Request, u *User) {
	var req keysReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, "bad request")
		return
	}
	if len(req.KemPK) != kemPKLen || len(req.SigVK) != sigVKLen || len(req.WrappedKeys) != wrappedLen ||
		!bytes.HasPrefix(req.WrappedKeys, []byte("SDKW")) {
		httpError(w, http.StatusBadRequest, "keys have the wrong size or format")
		return
	}
	if err := a.store.SetKeys(u.ID, req.KemPK, req.SigVK, req.WrappedKeys); err != nil {
		httpError(w, http.StatusConflict, "keys are already set for this account")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// GET /api/users/{username}/keys  (public: anyone may fetch public keys)
func (a *API) UserKeys(w http.ResponseWriter, r *http.Request) {
	u, err := a.store.UserByName(r.PathValue("username"))
	if err != nil || u.KemPK == nil {
		httpError(w, http.StatusNotFound, "no such user")
		return
	}
	writeJSON(w, map[string]string{"username": u.Username, "kem_pk": b64(u.KemPK), "sig_vk": b64(u.SigVK)})
}

type uploadReq struct {
	Recipient string `json:"recipient"`
	Blob      []byte `json:"blob"`
}

// POST /api/files
func (a *API) Upload(w http.ResponseWriter, r *http.Request, u *User) {
	var req uploadReq
	// base64 makes the JSON about 4/3 the size of the blob.
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxUploadSize*4/3+4096)).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, "bad request or file too large")
		return
	}
	if len(req.Blob) < minSealedLen || !bytes.HasPrefix(req.Blob, sealedMagic) {
		httpError(w, http.StatusBadRequest, "not a SealDrop file")
		return
	}
	if rcpt, err := a.store.UserByName(req.Recipient); err != nil || rcpt.KemPK == nil {
		httpError(w, http.StatusNotFound, "no such recipient")
		return
	}
	id := randomToken()[:32]
	if err := a.store.PutFile(id, u.Username, req.Recipient, req.Blob); err != nil {
		log.Printf("put file: %v", err)
		httpError(w, http.StatusInternalServerError, "could not store file")
		return
	}
	writeJSON(w, map[string]string{"id": id})
}

// GET /api/files
func (a *API) List(w http.ResponseWriter, r *http.Request, u *User) {
	files, err := a.store.ListFiles(u.Username)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "could not list files")
		return
	}
	writeJSON(w, files)
}

// GET /api/files/{id}
func (a *API) Download(w http.ResponseWriter, r *http.Request, u *User) {
	blob, err := a.store.GetFile(r.PathValue("id"), u.Username)
	if err != nil {
		httpError(w, http.StatusNotFound, "no such file")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(blob)
}
