package main

// agentapi.go: the API agents call, under /agent/v1/. Every handler is
// wrapped by agentRoute, which verifies the token and DPoP proof, loads the
// grant, and asks Decide. A handler only runs after an Allow.

import (
	"bytes"
	"crypto/sha3"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// AgentCtx is what an allowed handler gets to work with.
type AgentCtx struct {
	Claims *AccessClaims
	Grant  *Grant
	Agent  *Agent
	Body   []byte
}

type agentHandler func(w http.ResponseWriter, r *http.Request, c *AgentCtx)

type shareBody struct {
	Recipient string `json:"recipient"`
	Blob      []byte `json:"blob"`
}

type uploadBody struct {
	Blob []byte `json:"blob"`
}

// authenticate verifies "Authorization: DPoP <token>" and the DPoP proof.
// It returns claims, or a reason why not.
func (a *API) authenticate(r *http.Request) (*AccessClaims, string) {
	scheme, tok, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "DPoP") || tok == "" {
		return nil, "missing DPoP access token"
	}
	claims, err := a.issuer.VerifyAccessToken(tok)
	if err != nil {
		return nil, "access token invalid: " + err.Error()
	}
	proof := r.Header.Get("DPoP")
	if proof == "" {
		return claims, "missing DPoP proof"
	}
	if err := a.issuer.VerifyDPoP(proof, r.Method, a.issuer.origin+r.URL.Path, tok, claims.Cnf.JKT); err != nil {
		return claims, "DPoP proof invalid: " + err.Error()
	}
	return claims, ""
}

// agentRoute is the single gate: authenticate, load grant, Decide, then run h.
func (a *API) agentRoute(action string, h agentHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		in := PolicyInput{Now: a.issuer.now(), Action: action, FileID: r.PathValue("id")}
		claims, authErr := a.authenticate(r)
		in.AuthError = authErr
		if authErr == "" {
			in.Token = claims
			if g, err := a.store.GrantByID(claims.GrantID); err == nil {
				in.Grant = g
			}
		}
		var body []byte
		if r.Method == http.MethodPost && authErr == "" {
			var err error
			body, err = io.ReadAll(http.MaxBytesReader(w, r.Body, maxUploadSize*4/3+4096))
			if err != nil {
				httpError(w, http.StatusRequestEntityTooLarge, "request too large")
				return
			}
			if action == "share" {
				var sb struct {
					Recipient string `json:"recipient"`
				}
				json.Unmarshal(body, &sb)
				in.ShareTo = sb.Recipient
			}
		}

		start := time.Now()
		d := Decide(in)
		if err := a.recordDecision(r, in, d, time.Since(start)); err != nil && d.Allow {
			// Fail closed: an action we can't record is an action we don't allow.
			httpError(w, http.StatusServiceUnavailable, "audit log unavailable")
			return
		}

		if !d.Allow {
			if authErr != "" {
				w.Header().Set("WWW-Authenticate", `DPoP error="invalid_token"`)
				httpError(w, http.StatusUnauthorized, d.Reason)
			} else {
				httpError(w, http.StatusForbidden, d.Reason)
			}
			return
		}
		agent, err := a.store.AgentByID(claims.Act.Sub)
		if err != nil {
			httpError(w, http.StatusForbidden, "agent no longer registered")
			return
		}
		h(w, r, &AgentCtx{Claims: claims, Grant: in.Grant, Agent: agent, Body: body})
	}
}

// recordDecision writes the audit row for one policy decision.
func (a *API) recordDecision(r *http.Request, in PolicyInput, d Decision, took time.Duration) error {
	e := AuditEntry{
		RequestID: requestID(r), Actor: "unknown", Action: in.Action, FileID: in.FileID,
		Decision: decisionWord(d.Allow), Reason: d.Reason,
	}
	if in.Token != nil {
		// Only *verified* claims are recorded; an unverifiable token stays "unknown".
		e.Actor, e.OnBehalfOf, e.GrantID = in.Token.Act.Sub, in.Token.Subject, in.Token.GrantID
	}
	if in.Action == "share" && in.ShareTo != "" {
		e.Reason += " (recipient " + in.ShareTo + ")"
	}
	observePolicy(in.Action, d, took)
	if !d.Allow {
		slog.Warn("agent request denied", "request_id", e.RequestID, "actor", e.Actor, "on_behalf_of", e.OnBehalfOf,
			"action", e.Action, "file_id", e.FileID, "reason", d.Reason)
	}
	return a.store.Audit(e)
}

// GET /agent/v1/files: metadata of the files in the grant.
func (a *API) AgentList(w http.ResponseWriter, r *http.Request, c *AgentCtx) {
	all, err := a.store.ListFiles(c.Grant.Username)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "could not list files")
		return
	}
	out := []FileMeta{}
	for _, f := range all {
		for _, id := range c.Grant.FileIDs {
			if f.ID == id && f.Recipient == c.Grant.Username {
				out = append(out, f)
			}
		}
	}
	writeJSON(w, out)
}

// GET /agent/v1/files/{id}: the sealed blob plus the file key wrapped to this agent.
func (a *API) AgentDownload(w http.ResponseWriter, r *http.Request, c *AgentCtx) {
	id := r.PathValue("id")
	blob, err := a.store.GetFile(id, c.Grant.Username)
	if err != nil {
		httpError(w, http.StatusNotFound, "no such file")
		return
	}
	sender, wrapped, err := a.store.AgentFileKey(c.Grant.ID, id)
	if err != nil {
		httpError(w, http.StatusNotFound, "no such file")
		return
	}
	writeJSON(w, map[string]any{"id": id, "sender": sender, "blob": b64(blob), "wrapped_key": b64(wrapped)})
}

// checkAgentBlob: a sealed file uploaded by an agent must name the agent as
// its signer (header bytes 10..42 = SHA3-256 of the agent's ML-DSA key), so an
// agent can't pass a file off as coming from someone else.
func checkAgentBlob(blob []byte, ag *Agent) string {
	if len(blob) < minSealedLen || !bytes.HasPrefix(blob, sealedMagic) {
		return "not a SealDrop file"
	}
	fp := sha3.Sum256(ag.SigVK)
	if !bytes.Equal(blob[10:42], fp[:]) {
		return "file is not signed by this agent's key"
	}
	return ""
}

// POST /agent/v1/files: upload a file *to the user the agent acts for*.
func (a *API) AgentUpload(w http.ResponseWriter, r *http.Request, c *AgentCtx) {
	var req uploadBody
	if err := json.Unmarshal(c.Body, &req); err != nil {
		httpError(w, http.StatusBadRequest, "bad request")
		return
	}
	if why := checkAgentBlob(req.Blob, c.Agent); why != "" {
		httpError(w, http.StatusBadRequest, why)
		return
	}
	id := randomToken()[:32]
	if err := a.store.PutAgentFile(id, c.Agent.ID, c.Grant.Username, c.Grant.Username, req.Blob); err != nil {
		httpError(w, http.StatusInternalServerError, "could not store file")
		return
	}
	writeJSON(w, map[string]string{"id": id})
}

// POST /agent/v1/files/{id}/share: send a re-encrypted copy of a granted file
// to a recipient the grant allows. The agent decrypts and re-seals locally.
func (a *API) AgentShare(w http.ResponseWriter, r *http.Request, c *AgentCtx) {
	var req shareBody
	if err := json.Unmarshal(c.Body, &req); err != nil {
		httpError(w, http.StatusBadRequest, "bad request")
		return
	}
	if why := checkAgentBlob(req.Blob, c.Agent); why != "" {
		httpError(w, http.StatusBadRequest, why)
		return
	}
	id := randomToken()[:32]
	if err := a.store.PutAgentFile(id, c.Agent.ID, req.Recipient, c.Grant.Username, req.Blob); err != nil {
		httpError(w, http.StatusInternalServerError, "could not store file")
		return
	}
	writeJSON(w, map[string]string{"id": id})
}
