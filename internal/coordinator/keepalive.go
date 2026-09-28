package coordinator

import (
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
)

// Default keepalive timing for the coordinator gRPC server.
const (
	DefaultKeepaliveTime    = 30 * time.Second
	DefaultKeepaliveTimeout = 10 * time.Second
	minClientPingInterval   = 10 * time.Second
)

// ServerKeepalive makes the coordinator ping idle connections. The pings keep
// router streams alive through idle-killing proxies (HAProxy in front of the
// coordinator closes connections idle for 2 minutes), and a connection whose
// peer stops acknowledging them is closed after Timeout, so a router that died
// silently is unregistered instead of being counted in the quota split.
type ServerKeepalive struct {
	Time    time.Duration
	Timeout time.Duration
}

// ServerOptions returns the gRPC server options for k. Clients are allowed to
// ping as often as every 10 seconds, also without an active stream; the
// grpc-go default of 5 minutes would answer faster pings with GOAWAY.
func (k ServerKeepalive) ServerOptions() []grpc.ServerOption {
	return []grpc.ServerOption{
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    k.Time,
			Timeout: k.Timeout,
		}),
		grpc.KeepaliveEnforcementPolicy(clientPingPolicy()),
	}
}

func clientPingPolicy() keepalive.EnforcementPolicy {
	return keepalive.EnforcementPolicy{
		MinTime:             minClientPingInterval,
		PermitWithoutStream: true,
	}
}
