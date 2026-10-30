package main

// policy.go: THE authorization decision for agent requests.
//
// Every agent request, valid or not, ends in exactly one call to Decide.
// Decide is a pure function (no I/O, no clock of its own), so it's easy to
// test exhaustively and to time. Deny by default: it returns Allow only after
// every check below has passed, in this order.

import (
	"slices"
	"strings"
	"time"
)

type PolicyInput struct {
	Now       time.Time
	AuthError string        // set if the access token or DPoP proof failed verification
	Token     *AccessClaims // verified access token claims (nil if AuthError is set)
	Grant     *Grant        // the grant the token names, loaded fresh from the database (nil if gone)
	Action    string        // list | download | upload | share
	FileID    string        // for download and share
	ShareTo   string        // for share
}

type Decision struct {
	Allow  bool
	Reason string
}

func deny(reason string) Decision { return Decision{Allow: false, Reason: reason} }

// Decide answers: may this agent do this action, on this file, for this user, right now?
func Decide(in PolicyInput) Decision {
	switch {
	case in.AuthError != "":
		return deny("authentication failed: " + in.AuthError)
	case in.Token == nil:
		return deny("no verified token")
	case !slices.Contains(allActions, in.Action):
		return deny("unknown action")
	case in.Grant == nil:
		return deny("grant not found")
	case in.Grant.ID != in.Token.GrantID:
		return deny("token names a different grant")
	case in.Grant.AgentID != in.Token.Act.Sub || in.Token.ClientID != in.Token.Act.Sub:
		return deny("token was issued to a different agent")
	case in.Grant.Username != in.Token.Subject:
		return deny("token acts for a different user")
	case in.Grant.RevokedAt != nil:
		return deny("grant revoked")
	case in.Now.Unix() >= in.Grant.ExpiresAt:
		return deny("grant expired")
	case !slices.Contains(strings.Fields(in.Token.Scope), in.Action):
		return deny("action not in token scope")
	case !slices.Contains(in.Grant.Actions, in.Action):
		return deny("action not granted")
	}
	if in.Action == "download" || in.Action == "share" {
		if in.FileID == "" || !slices.Contains(in.Grant.FileIDs, in.FileID) {
			return deny("file not in grant")
		}
	}
	if in.Action == "share" && !slices.Contains(in.Grant.ShareWith, in.ShareTo) {
		return deny("share recipient not allowed by grant")
	}
	return Decision{Allow: true, Reason: "allowed by grant " + in.Grant.ID}
}
