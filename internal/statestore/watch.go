package statestore

import (
	"context"
	"fmt"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
)

// watchPrefix returns after the watch exists on the server. Starting it inside
// a goroutine after returning loses mutations made immediately by the caller.
func (s *EtcdStore) watchPrefix(ctx context.Context, prefix string) (clientv3.WatchChan, context.CancelFunc, error) {
	watchCtx, cancel := context.WithCancel(ctx)
	events := s.client.Watch(watchCtx, prefix, clientv3.WithPrefix(), clientv3.WithCreatedNotify())
	timer := time.NewTimer(defaultDialTimeout)
	defer timer.Stop()
	select {
	case first, ok := <-events:
		if !ok || first.Err() != nil || !first.Created {
			cancel()
			return nil, nil, fmt.Errorf("etcd watch registration failed")
		}
		return events, cancel, nil
	case <-ctx.Done():
		cancel()
		return nil, nil, ctx.Err()
	case <-timer.C:
		cancel()
		return nil, nil, fmt.Errorf("etcd watch registration timed out")
	}
}
