package statestore

import "context"

// TokenState contains no credential bytes. Pending fences the non-atomic object
// write. A failed/unknown write stays fenced rather than claiming success.
type TokenState struct {
	Revision        int64  `json:"-"`
	Pending         string `json:"pending,omitempty"`
	Version         string `json:"version,omitempty"`
	CredentialID    string `json:"credential_id,omitempty"`
	RejectedID      string `json:"rejected_id,omitempty"`
	RejectedVersion string `json:"rejected_version,omitempty"`
}

type TokenEvent struct{ Ref string }

// TokenStates is optional control-plane metadata storage. Get is linearizable;
// CAS returns the assigned revision, or zero when another writer won. Watches
// are an eviction optimization: requested-ref reads remain authoritative after
// reconnect, compaction and dropped notifications. No S3 listing is involved.
type TokenStates interface {
	GetTokenState(context.Context, string) (TokenState, error)
	CASTokenState(context.Context, string, int64, TokenState) (int64, error)
	WatchTokenStates(context.Context) (<-chan TokenEvent, error)
}
