package statestore

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	clientv3 "go.etcd.io/etcd/client/v3"
)

func (s *EtcdStore) tokenPrefix() string { return s.prefix + "/token-states/" }
func (s *EtcdStore) tokenKey(ref string) string {
	return s.tokenPrefix() + base64.RawURLEncoding.EncodeToString([]byte(ref))
}
func (s *EtcdStore) GetTokenState(ctx context.Context, ref string) (TokenState, error) {
	resp, err := s.client.Get(ctx, s.tokenKey(ref))
	if err != nil {
		return TokenState{}, err
	}
	if len(resp.Kvs) == 0 {
		return TokenState{}, nil
	}
	var state TokenState
	if err = json.Unmarshal(resp.Kvs[0].Value, &state); err != nil {
		return state, fmt.Errorf("invalid token state: %w", err)
	}
	state.Revision = resp.Kvs[0].ModRevision
	return state, nil
}
func (s *EtcdStore) CASTokenState(ctx context.Context, ref string, rev int64, state TokenState) (int64, error) {
	body, err := json.Marshal(state)
	if err != nil {
		return 0, err
	}
	resp, err := s.client.Txn(ctx).If(clientv3.Compare(clientv3.ModRevision(s.tokenKey(ref)), "=", rev)).Then(clientv3.OpPut(s.tokenKey(ref), string(body))).Commit()
	if err != nil {
		return 0, err
	}
	if !resp.Succeeded {
		return 0, nil
	}
	return resp.Header.Revision, nil
}
func (s *EtcdStore) WatchTokenStates(ctx context.Context) (<-chan TokenEvent, error) {
	events, cancel, err := s.watchPrefix(ctx, s.tokenPrefix())
	if err != nil {
		return nil, err
	}
	out := make(chan TokenEvent, 64)
	go func() {
		defer close(out)
		defer cancel()
		// No snapshot required: every requested ref is checked linearly. A canceled
		// watch is restarted by the caller; a gap cannot authorize cached data.
		for resp := range events {
			if resp.Canceled {
				return
			}
			for _, ev := range resp.Events {
				raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(string(ev.Kv.Key), s.tokenPrefix()))
				if err != nil {
					continue
				}
				select {
				case out <- TokenEvent{Ref: string(raw)}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return out, nil
}
