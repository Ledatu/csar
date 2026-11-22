package statestore

import (
	"context"
	"errors"
	"testing"

	clientv3 "go.etcd.io/etcd/client/v3"
)

type cleanupKV struct{ clientv3.KV }

func (*cleanupKV) Delete(context.Context, string, ...clientv3.OpOption) (*clientv3.DeleteResponse, error) {
	return &clientv3.DeleteResponse{}, nil
}

type cleanupLease struct {
	clientv3.Lease
	err     error
	revoked clientv3.LeaseID
}

func (l *cleanupLease) Revoke(_ context.Context, id clientv3.LeaseID) (*clientv3.LeaseRevokeResponse, error) {
	l.revoked = id
	return &clientv3.LeaseRevokeResponse{}, l.err
}

func TestUnregisterRouterReportsLeaseRevokeFailure(t *testing.T) {
	want := errors.New("revoke unavailable")
	lease := &cleanupLease{err: want}
	s := &EtcdStore{
		client: &clientv3.Client{KV: &cleanupKV{}, Lease: lease},
		leases: map[string]clientv3.LeaseID{"router": 7},
	}
	if err := s.UnregisterRouter(context.Background(), "router"); !errors.Is(err, want) {
		t.Fatalf("lease revoke error was lost: %v", err)
	}
	if lease.revoked != 7 || len(s.leases) != 0 {
		t.Fatal("failed lease revocation retained disconnected router state")
	}
	lease.err = nil
	s.leases["router"] = 8
	if err := s.UnregisterRouter(context.Background(), "router"); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.leases["router"]; ok || lease.revoked != 8 {
		t.Fatal("successful lease revocation retained stale state")
	}
}
