// Package grpcclient provides a gRPC client for the csar-helper to communicate
// with the CSAR Coordinator for config push and status operations.
package grpcclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"
	"time"

	csarv1 "github.com/ledatu/csar/proto/csar/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// AdminClient connects to the CSAR Coordinator for management operations.
type AdminClient struct {
	conn   *grpc.ClientConn
	coord  csarv1.CoordinatorServiceClient
	logger *slog.Logger
}

// ConnectOptions configures the coordinator connection.
type ConnectOptions struct {
	// Address is the coordinator gRPC address (host:port).
	Address string

	// CAFile is the path to the CA certificate for TLS verification.
	CAFile string

	// CertFile and KeyFile for mutual TLS (optional).
	CertFile string
	KeyFile  string

	// Insecure allows plaintext connection (dev only).
	Insecure bool

	// Timeout for the connection attempt.
	Timeout time.Duration

	Logger *slog.Logger
}

// Connect establishes a gRPC connection to the coordinator.
func Connect(opts ConnectOptions) (*AdminClient, error) {
	if opts.Address == "" {
		return nil, fmt.Errorf("coordinator address is required")
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Timeout == 0 {
		opts.Timeout = 10 * time.Second
	}

	var dialOpts []grpc.DialOption

	if opts.Insecure {
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		tlsCfg := &tls.Config{
			MinVersion: tls.VersionTLS12,
		}

		// Load CA
		if opts.CAFile != "" {
			caCert, err := os.ReadFile(opts.CAFile)
			if err != nil {
				return nil, fmt.Errorf("reading CA file: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(caCert) {
				return nil, fmt.Errorf("failed to parse CA certificate")
			}
			tlsCfg.RootCAs = pool
		}

		// Load client cert for mTLS
		if opts.CertFile != "" && opts.KeyFile != "" {
			cert, err := tls.LoadX509KeyPair(opts.CertFile, opts.KeyFile)
			if err != nil {
				return nil, fmt.Errorf("loading client certificate: %w", err)
			}
			tlsCfg.Certificates = []tls.Certificate{cert}
		}

		dialOpts = append(dialOpts, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	}

	// Block until the connection is actually established (or timeout).
	// Without WithBlock, DialContext returns immediately and failures surface
	// only on the first RPC — misleading for CLI users.
	dialOpts = append(dialOpts, grpc.WithBlock())

	ctx, cancel := context.WithTimeout(context.Background(), opts.Timeout)
	defer cancel()

	opts.Logger.Info("connecting to coordinator…", "address", opts.Address, "timeout", opts.Timeout)

	dialStart := time.Now()
	conn, err := grpc.DialContext(ctx, opts.Address, dialOpts...)
	dialDuration := time.Since(dialStart)
	if err != nil {
		return nil, fmt.Errorf("connecting to coordinator at %s (failed after %s): %w", opts.Address, dialDuration.Round(time.Millisecond), err)
	}

	opts.Logger.Info("connected to coordinator (transport ready)", "address", opts.Address, "dial_duration", dialDuration.Round(time.Millisecond))

	return &AdminClient{
		conn:   conn,
		coord:  csarv1.NewCoordinatorServiceClient(conn),
		logger: opts.Logger,
	}, nil
}

// Close closes the gRPC connection.
func (c *AdminClient) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// ReportHealth sends a health report to the coordinator.
func (c *AdminClient) ReportHealth(ctx context.Context, routerID string, healthy bool) error {
	_, err := c.coord.ReportHealth(ctx, &csarv1.HealthReport{
		RouterId: routerID,
		Healthy:  healthy,
		Metadata: map[string]string{
			"source": "csar-helper",
		},
	})
	return err
}

// CoordinatorClient returns the underlying coordinator service client.
func (c *AdminClient) CoordinatorClient() csarv1.CoordinatorServiceClient {
	return c.coord
}
