package main

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/ledatu/csar/internal/tui"
	"github.com/spf13/cobra"
)

var (
	benchURL         string
	benchMethod      string
	benchConcurrency int
	benchDuration    time.Duration
	benchHeaders     []string
)

var benchCmd = &cobra.Command{
	Use:   "bench",
	Short: "Built-in HTTP benchmark with live TUI progress",
	Long: `Runs an HTTP load benchmark against a target URL with a live terminal UI
showing progress, requests per second, and latency distribution.

Results include P50/P95/P99 latencies and a histogram.`,
	Aliases: []string{"benchmark"},
	Example: `  # Quick benchmark
  csar-helper bench --url http://localhost:8080/api/health

  # Heavy load test
  csar-helper bench --url http://localhost:8080/api/users \
    --method GET --concurrency 50 --duration 30s

  # With custom headers
  csar-helper bench --url http://localhost:8080/api/data \
    --header "Authorization: Bearer token123"`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if benchURL == "" {
			return fmt.Errorf("--url is required")
		}

		headers := make(map[string]string)
		for _, h := range benchHeaders {
			colonIdx := strings.Index(h, ":")
			if colonIdx <= 0 {
				return fmt.Errorf("invalid --header %q: expected format \"Key: Value\"", h)
			}
			key := strings.TrimSpace(h[:colonIdx])
			val := strings.TrimSpace(h[colonIdx+1:])
			if key == "" {
				return fmt.Errorf("invalid --header %q: empty header name", h)
			}
			headers[key] = val
		}

		cfg := tui.BenchConfig{
			URL:         benchURL,
			Method:      benchMethod,
			Concurrency: benchConcurrency,
			Duration:    benchDuration,
			Headers:     headers,
		}

		model := tui.NewBench(cfg)
		p := tea.NewProgram(model, tea.WithAltScreen())
		_, err := p.Run()
		return err
	},
}

func init() {
	benchCmd.Flags().StringVar(&benchURL, "url", "", "target URL (required)")
	benchCmd.Flags().StringVar(&benchMethod, "method", "GET", "HTTP method")
	benchCmd.Flags().IntVar(&benchConcurrency, "concurrency", 10, "number of concurrent workers")
	benchCmd.Flags().DurationVar(&benchDuration, "duration", 10*time.Second, "benchmark duration")
	benchCmd.Flags().StringSliceVar(&benchHeaders, "header", nil, `HTTP headers ("Key: Value", repeatable)`)

	rootCmd.AddCommand(benchCmd)
}
