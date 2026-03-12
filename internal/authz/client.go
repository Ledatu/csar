// Package authz provides a gRPC client for the csar-authz authorization service.
package authz

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	authzv1 "github.com/ledatu/csar-proto/csar/authz/v1"
	"github.com/ledatu/csar/internal/config"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// Client wraps the csar-authz gRPC connection.
type Client struct {
	client  authzv1.AuthzServiceClient
	conn    *grpc.ClientConn
	timeout time.Duration
	logger  *slog.Logger
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

	var creds credentials.TransportCredentials
	switch {
	case cfg.AllowInsecure:
		creds = insecure.NewCredentials()
	case cfg.CAFile != "":
		var err error
		creds, err = credentials.NewClientTLSFromFile(cfg.CAFile, "")
		if err != nil {
			return nil, fmt.Errorf("authz TLS from CA: %w", err)
		}
	default:
		creds = credentials.NewTLS(nil)
	}

	conn, err := grpc.NewClient(cfg.Address, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, fmt.Errorf("authz grpc dial: %w", err)
	}

	logger.Info("authz client connected", "address", cfg.Address, "timeout", timeout)

	return &Client{
		client:  authzv1.NewAuthzServiceClient(conn),
		conn:    conn,
		timeout: timeout,
		logger:  logger,
	}, nil
}

// CheckAccessResult holds the outcome of a CheckAccess call.
type CheckAccessResult struct {
	Allowed         bool
	MatchedRoles    []string
	EnrichedHeaders map[string]string
}

// CheckAccess evaluates an authorization request against csar-authz.
func (c *Client) CheckAccess(ctx context.Context, req *authzv1.CheckAccessRequest) (*CheckAccessResult, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

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
