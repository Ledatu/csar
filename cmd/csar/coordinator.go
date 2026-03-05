package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"

	"github.com/ledatu/csar/internal/config"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	grpcinsecure "google.golang.org/grpc/credentials/insecure"
)

// dialCoordinator creates a gRPC client connection to the coordinator.
// It enforces TLS by default — plaintext requires explicit allow_insecure: true.
func dialCoordinator(coordCfg config.CoordinatorConfig, logger *slog.Logger) (*grpc.ClientConn, error) {
	var dialOpt grpc.DialOption

	switch {
	case coordCfg.CAFile != "":
		// TLS (or mTLS) to the coordinator.
		caCert, err := os.ReadFile(coordCfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("reading coordinator CA file %s: %w", coordCfg.CAFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("coordinator CA file %s contains no valid certificates", coordCfg.CAFile)
		}

		tlsCfg := &tls.Config{
			RootCAs:    pool,
			MinVersion: tls.VersionTLS13,
		}

		// If client cert+key are provided, enable mTLS.
		if coordCfg.CertFile != "" && coordCfg.KeyFile != "" {
			clientCert, err := tls.LoadX509KeyPair(coordCfg.CertFile, coordCfg.KeyFile)
			if err != nil {
				return nil, fmt.Errorf("loading coordinator client cert/key: %w", err)
			}
			tlsCfg.Certificates = []tls.Certificate{clientCert}
			logger.Info("coordinator gRPC: mTLS enabled",
				"ca", coordCfg.CAFile,
				"cert", coordCfg.CertFile,
			)
		} else {
			logger.Info("coordinator gRPC: TLS enabled (server-auth only)",
				"ca", coordCfg.CAFile,
			)
		}

		dialOpt = grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg))

	case coordCfg.AllowInsecure:
		// Explicit dev-mode opt-in for plaintext.
		logger.Warn("WARNING: coordinator gRPC connection is INSECURE (plaintext). " +
			"Set coordinator.ca_file for production use.")
		dialOpt = grpc.WithTransportCredentials(grpcinsecure.NewCredentials())

	default:
		return nil, fmt.Errorf("coordinator.ca_file is required for secure gRPC transport; " +
			"set coordinator.allow_insecure: true only for local development")
	}

	conn, err := grpc.NewClient(coordCfg.Address, dialOpt)
	if err != nil {
		return nil, fmt.Errorf("dialing coordinator at %s: %w", coordCfg.Address, err)
	}
	return conn, nil
}
