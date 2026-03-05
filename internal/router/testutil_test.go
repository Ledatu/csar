package router

import (
	"io"
	"log/slog"

	"github.com/ledatu/csar/internal/config"
)

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newTestConfig(routes map[string]config.PathConfig) *config.Config {
	return &config.Config{
		ListenAddr: ":8080",
		Paths:      routes,
	}
}

func containsSubstr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
