package audit

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	auditcore "github.com/ledatu/csar-core/audit"
	"github.com/ledatu/csar-core/grpcdial"
	"github.com/ledatu/csar/internal/config"
	"google.golang.org/grpc"
)

// Client wraps csar-core/audit.Client with a managed gRPC connection.
type Client struct {
	core *auditcore.Client
	conn *grpc.ClientConn
}

// New creates a Client from AuditClientConfig.
// Returns nil without error when cfg is nil (audit disabled).
func New(cfg *config.AuditClientConfig, logger *slog.Logger) (*Client, error) {
	if cfg == nil {
		return nil, nil
	}

	timeout := cfg.Timeout.Duration
	if timeout == 0 {
		timeout = 500 * time.Millisecond
	}

	conn, err := grpcdial.Dial(&grpcdial.Config{
		Address:        cfg.Address,
		Insecure:       cfg.AllowInsecure,
		CAFile:         cfg.CAFile,
		CertFile:       cfg.CertFile,
		KeyFile:        cfg.KeyFile,
		DefaultTimeout: timeout,
	}, logger)
	if err != nil {
		return nil, fmt.Errorf("audit: %w", err)
	}

	transport := auditcore.NewGRPCSingleTransport(conn)

	core, err := auditcore.NewClient(auditcore.ClientConfig{
		Transport: transport,
	}, logger)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("audit: creating client: %w", err)
	}

	return &Client{core: core, conn: conn}, nil
}

// Record enqueues an audit event asynchronously. Never blocks the caller.
func (c *Client) Record(_ context.Context, ev *auditcore.Event) {
	if c == nil || c.core == nil {
		return
	}
	c.core.Record(context.Background(), ev)
}

// Close drains queued events, then closes the gRPC connection.
func (c *Client) Close() error {
	var errs []error
	if c.core != nil {
		if err := c.core.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if c.conn != nil {
		if err := c.conn.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
