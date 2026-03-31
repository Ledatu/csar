package main

import (
	"fmt"
	"log/slog"

	"github.com/ledatu/csar-core/grpcdial"
	"github.com/ledatu/csar/internal/config"
	"google.golang.org/grpc"
)

func dialCoordinator(coordCfg config.CoordinatorConfig, logger *slog.Logger) (*grpc.ClientConn, error) {
	conn, err := grpcdial.Dial(&grpcdial.Config{
		Address:   coordCfg.Address,
		Insecure:  coordCfg.AllowInsecure,
		RequireCA: true,
		CAFile:    coordCfg.CAFile,
		CertFile:  coordCfg.CertFile,
		KeyFile:   coordCfg.KeyFile,
	}, logger)
	if err != nil {
		return nil, fmt.Errorf("coordinator: %w", err)
	}
	return conn, nil
}
