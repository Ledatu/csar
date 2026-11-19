package statestore

import "context"

func (m *MemoryStore) GetTokenState(ctx context.Context, ref string) (TokenState, error) {
	if err := ctx.Err(); err != nil {
		return TokenState{}, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.tokenStates[ref], nil
}
func (m *MemoryStore) CASTokenState(ctx context.Context, ref string, rev int64, state TokenState) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.tokenStates[ref].Revision != rev {
		return 0, nil
	}
	if m.tokenStates == nil {
		m.tokenStates = make(map[string]TokenState)
	}
	m.tokenRevision++
	state.Revision = m.tokenRevision
	m.tokenStates[ref] = state
	for ch := range m.tokenWatchers {
		select {
		case ch <- TokenEvent{Ref: ref}:
		default:
		}
	}
	return state.Revision, nil
}
func (m *MemoryStore) WatchTokenStates(ctx context.Context) (<-chan TokenEvent, error) {
	ch := make(chan TokenEvent, 64)
	m.mu.Lock()
	if m.tokenWatchers == nil {
		m.tokenWatchers = make(map[chan TokenEvent]struct{})
	}
	m.tokenWatchers[ch] = struct{}{}
	m.mu.Unlock()
	go func() {
		<-ctx.Done()
		m.mu.Lock()
		if _, ok := m.tokenWatchers[ch]; ok {
			delete(m.tokenWatchers, ch)
			close(ch)
		}
		m.mu.Unlock()
	}()
	return ch, nil
}
