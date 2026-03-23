// Package authz provides a gRPC client for the csar-authz authorization service.
package authz

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/ledatu/csar-core/authzclient"
	authzv1 "github.com/ledatu/csar-proto/csar/authz/v1"
	"github.com/ledatu/csar/internal/config"
	"google.golang.org/grpc"
)

// Client wraps the csar-authz gRPC connection.
type Client struct {
	client authzv1.AuthzServiceClient
	conn   *grpc.ClientConn
	logger *slog.Logger
}

// New creates a Client from AuthzClientConfig.
// Returns nil without error when cfg is nil (authz disabled).
func New(cfg *config.AuthzClientConfig, logger *slog.Logger) (*Client, error) {
	if cfg == nil {
		return nil, nil
	}

	timeout := cfg.Timeout.Duration
	if timeout == 0 {
		timeout = 500 * time.Millisecond
	}

	conn, client, err := authzclient.Dial(&authzclient.Config{
		Address:        cfg.Address,
		Insecure:       cfg.AllowInsecure,
		CAFile:         cfg.CAFile,
		CertFile:       cfg.CertFile,
		KeyFile:        cfg.KeyFile,
		DefaultTimeout: timeout,
	}, logger)
	if err != nil {
		return nil, fmt.Errorf("authz grpc dial: %w", err)
	}

	return &Client{
		client: client,
		conn:   conn,
		logger: logger,
	}, nil
}

// CheckAccessResult holds the outcome of a CheckAccess call.
type CheckAccessResult struct {
	Allowed         bool
	MatchedRoles    []string
	EnrichedHeaders map[string]string
}

// CheckAccess evaluates an authorization request against csar-authz.
// Per-call timeout is handled by the authzclient.Dial interceptor.
func (c *Client) CheckAccess(ctx context.Context, req *authzv1.CheckAccessRequest) (*CheckAccessResult, error) {
	resp, err := c.client.CheckAccess(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("authz CheckAccess: %w", err)
	}

	return &CheckAccessResult{
		Allowed:         resp.GetAllowed(),
		MatchedRoles:    resp.GetMatchedRoles(),
		EnrichedHeaders: resp.GetEnrichedHeaders(),
	}, nil
}

// Close shuts down the gRPC connection.
func (c *Client) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}
