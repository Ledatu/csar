package tui

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// ─── Benchmark config ──────────────────────────────────────────────────────────

// BenchConfig configures a benchmark run.
type BenchConfig struct {
	URL         string
	Method      string
	Concurrency int
	Duration    time.Duration
	Headers     map[string]string
}

// BenchResult contains the results of a benchmark run.
type BenchResult struct {
	TotalRequests int64
	SuccessCount  int64
	ErrorCount    int64
	Duration      time.Duration
	Latencies     []time.Duration
	StatusCodes   map[int]int64
	RPS           float64
	AvgLatency    time.Duration
	P50Latency    time.Duration
	P95Latency    time.Duration
	P99Latency    time.Duration
	MaxLatency    time.Duration
	MinLatency    time.Duration
}

// ─── Benchmark messages ────────────────────────────────────────────────────────

type benchTickMsg time.Time
type benchDoneMsg struct{ Result *BenchResult }
type benchProgressMsg struct {
	RequestsDone int64
	Elapsed      time.Duration
	CurrentRPS   float64
}

// ─── Benchmark model ───────────────────────────────────────────────────────────

// benchState is shared between the benchmark goroutine and the TUI model
// for live progress reporting.
type benchState struct {
	totalReqs atomic.Int64
	startTime time.Time
}

// BenchModel is the Bubble Tea model for the benchmark TUI.
type BenchModel struct {
	config      BenchConfig
	spinner     spinner.Model
	progress    progress.Model
	result      *BenchResult
	running     bool
	done        bool
	startTime   time.Time
	reqsDone    int64
	currentRPS  float64
	elapsed     time.Duration
	cancel      context.CancelFunc
	width       int
	state       *benchState // shared progress state
}

// NewBench creates a new benchmark TUI model.
func NewBench(cfg BenchConfig) BenchModel {
	sp := spinner.New()
	sp.Spinner = spinner.Dot
	sp.Style = lipgloss.NewStyle().Foreground(ColorPrimary)

	prog := progress.New(
		progress.WithDefaultGradient(),
		progress.WithWidth(50),
	)

	return BenchModel{
		config:   cfg,
		spinner:  sp,
		progress: prog,
		width:    80,
	}
}

func (m BenchModel) Init() tea.Cmd {
	m.state = &benchState{startTime: time.Now()}
	return tea.Batch(m.spinner.Tick, m.startBenchmark(), tickCmd())
}

func (m BenchModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "q" || msg.String() == "ctrl+c" {
			if m.cancel != nil {
				m.cancel()
			}
			return m, tea.Quit
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.progress.Width = msg.Width - 20

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd

	case benchTickMsg:
		// Poll shared state for live progress
		if m.state != nil && !m.done {
			m.reqsDone = m.state.totalReqs.Load()
			m.elapsed = time.Since(m.state.startTime)
			if m.elapsed > 0 {
				m.currentRPS = float64(m.reqsDone) / m.elapsed.Seconds()
			}
			pct := float64(m.elapsed) / float64(m.config.Duration)
			if pct > 1 {
				pct = 1
			}
			return m, tea.Batch(
				m.progress.SetPercent(pct),
				tickCmd(),
			)
		}
		return m, nil

	case benchProgressMsg:
		m.reqsDone = msg.RequestsDone
		m.elapsed = msg.Elapsed
		m.currentRPS = msg.CurrentRPS
		pct := float64(m.elapsed) / float64(m.config.Duration)
		if pct > 1 {
			pct = 1
		}
		return m, tea.Batch(
			m.progress.SetPercent(pct),
			tickCmd(),
		)

	case benchDoneMsg:
		m.result = msg.Result
		m.done = true
		m.running = false
		return m, nil

	case progress.FrameMsg:
		progressModel, cmd := m.progress.Update(msg)
		m.progress = progressModel.(progress.Model)
		return m, cmd
	}

	return m, nil
}

func (m BenchModel) View() string {
	var b strings.Builder

	title := TitleStyle.Render("  CSAR Benchmark")
	b.WriteString(title + "\n\n")

	// Config info
	cfgBox := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(ColorMuted).
		Padding(0, 2).
		Width(min(m.width-4, 60))

	cfgLines := []string{
		fmt.Sprintf("  %s %s %s", LabelStyle.Render("Target:"), MethodBadge(m.config.Method), m.config.URL),
		fmt.Sprintf("  %s %d goroutines", LabelStyle.Render("Concurrency:"), m.config.Concurrency),
		fmt.Sprintf("  %s %s", LabelStyle.Render("Duration:"), m.config.Duration),
	}
	b.WriteString(cfgBox.Render(strings.Join(cfgLines, "\n")) + "\n\n")

	if m.done && m.result != nil {
		b.WriteString(m.renderResults())
	} else {
		// Progress
		b.WriteString(fmt.Sprintf("  %s Running benchmark...\n\n", m.spinner.View()))
		b.WriteString("  " + m.progress.View() + "\n\n")
		b.WriteString(fmt.Sprintf("  Requests: %s   Elapsed: %s   RPS: %s\n",
			lipgloss.NewStyle().Bold(true).Foreground(ColorText).Render(fmt.Sprintf("%d", m.reqsDone)),
			DimStyle.Render(m.elapsed.Round(time.Millisecond).String()),
			lipgloss.NewStyle().Foreground(ColorSecondary).Render(fmt.Sprintf("%.0f", m.currentRPS)),
		))
	}

	b.WriteString("\n" + HelpStyle.Render("  q/ctrl+c to stop"))
	return b.String()
}

func (m BenchModel) renderResults() string {
	r := m.result
	var b strings.Builder

	// Summary box
	summaryBox := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(ColorSuccess).
		Padding(1, 2).
		Width(min(m.width-4, 60))

	summaryLines := []string{
		SuccessStyle.Render(fmt.Sprintf("  %s Benchmark Complete", IconCheck)),
		"",
		fmt.Sprintf("  %s %d", LabelStyle.Render("Total requests:"), r.TotalRequests),
		fmt.Sprintf("  %s %d", LabelStyle.Render("Successful:"), r.SuccessCount),
		fmt.Sprintf("  %s %d", LabelStyle.Render("Errors:"), r.ErrorCount),
		fmt.Sprintf("  %s %s", LabelStyle.Render("Duration:"), r.Duration.Round(time.Millisecond)),
		fmt.Sprintf("  %s %s", LabelStyle.Render("RPS:"),
			lipgloss.NewStyle().Bold(true).Foreground(ColorSecondary).Render(fmt.Sprintf("%.1f", r.RPS))),
	}
	b.WriteString(summaryBox.Render(strings.Join(summaryLines, "\n")) + "\n\n")

	// Latency box
	latencyBox := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(ColorAccent).
		Padding(1, 2).
		Width(min(m.width-4, 60))

	latencyLines := []string{
		SubtitleStyle.Render("  Latency Distribution"),
		"",
		fmt.Sprintf("  %s %s", LabelStyle.Render("Min:"), formatDuration(r.MinLatency)),
		fmt.Sprintf("  %s %s", LabelStyle.Render("Avg:"), formatDuration(r.AvgLatency)),
		fmt.Sprintf("  %s %s", LabelStyle.Render("P50:"), formatDuration(r.P50Latency)),
		fmt.Sprintf("  %s %s", LabelStyle.Render("P95:"), formatDuration(r.P95Latency)),
		fmt.Sprintf("  %s %s", LabelStyle.Render("P99:"), formatDuration(r.P99Latency)),
		fmt.Sprintf("  %s %s", LabelStyle.Render("Max:"), formatDuration(r.MaxLatency)),
	}

	// ASCII histogram
	if len(r.Latencies) > 0 {
		latencyLines = append(latencyLines, "")
		latencyLines = append(latencyLines, renderHistogram(r.Latencies, 40))
	}

	b.WriteString(latencyBox.Render(strings.Join(latencyLines, "\n")) + "\n\n")

	// Status codes
	if len(r.StatusCodes) > 0 {
		statusBox := lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(ColorMuted).
			Padding(0, 2).
			Width(min(m.width-4, 40))

		var statusLines []string
		statusLines = append(statusLines, SubtitleStyle.Render("  Status Codes"))
		statusLines = append(statusLines, "")
		for code, count := range r.StatusCodes {
			style := SuccessStyle
			if code >= 400 {
				style = WarningStyle
			}
			if code >= 500 {
				style = ErrorStyle
			}
			statusLines = append(statusLines, fmt.Sprintf("  %s %d",
				style.Render(fmt.Sprintf("  %d:", code)),
				count))
		}
		b.WriteString(statusBox.Render(strings.Join(statusLines, "\n")))
	}

	return b.String()
}

func (m BenchModel) startBenchmark() tea.Cmd {
	state := m.state
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), m.config.Duration+5*time.Second)
		defer cancel()

		result := runBenchmark(ctx, m.config, state)
		return benchDoneMsg{Result: result}
	}
}

func tickCmd() tea.Cmd {
	return tea.Tick(200*time.Millisecond, func(t time.Time) tea.Msg {
		return benchTickMsg(t)
	})
}

// runBenchmark executes the benchmark and collects results.
// The shared benchState lets the TUI model poll live request counts.
func runBenchmark(ctx context.Context, cfg BenchConfig, state *benchState) *BenchResult {
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        cfg.Concurrency * 2,
			MaxIdleConnsPerHost: cfg.Concurrency * 2,
			IdleConnTimeout:     30 * time.Second,
		},
	}

	var (
		successCnt atomic.Int64
		errorCnt   atomic.Int64
		mu         sync.Mutex
		latencies  []time.Duration
		statusMap  = make(map[int]int64)
	)

	start := time.Now()
	deadline := start.Add(cfg.Duration)

	var wg sync.WaitGroup
	for i := 0; i < cfg.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(deadline) {
				if ctx.Err() != nil {
					return
				}

				reqStart := time.Now()
				req, err := http.NewRequestWithContext(ctx, cfg.Method, cfg.URL, nil)
				if err != nil {
					errorCnt.Add(1)
					state.totalReqs.Add(1)
					continue
				}

				for k, v := range cfg.Headers {
					req.Header.Set(k, v)
				}

				resp, err := client.Do(req)
				lat := time.Since(reqStart)
				state.totalReqs.Add(1)

				if err != nil {
					errorCnt.Add(1)
				} else {
					resp.Body.Close()
					successCnt.Add(1)
					mu.Lock()
					latencies = append(latencies, lat)
					statusMap[resp.StatusCode]++
					mu.Unlock()
				}
			}
		}()
	}

	wg.Wait()
	elapsed := time.Since(start)

	// Compute statistics
	result := &BenchResult{
		TotalRequests: state.totalReqs.Load(),
		SuccessCount:  successCnt.Load(),
		ErrorCount:    errorCnt.Load(),
		Duration:      elapsed,
		Latencies:     latencies,
		StatusCodes:   statusMap,
	}

	if elapsed > 0 {
		result.RPS = float64(result.TotalRequests) / elapsed.Seconds()
	}

	if len(latencies) > 0 {
		sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })

		var total time.Duration
		for _, l := range latencies {
			total += l
		}
		result.AvgLatency = total / time.Duration(len(latencies))
		result.MinLatency = latencies[0]
		result.MaxLatency = latencies[len(latencies)-1]
		result.P50Latency = percentile(latencies, 0.50)
		result.P95Latency = percentile(latencies, 0.95)
		result.P99Latency = percentile(latencies, 0.99)
	}

	return result
}

func percentile(sorted []time.Duration, pct float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(math.Ceil(pct*float64(len(sorted)))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

func formatDuration(d time.Duration) string {
	if d < time.Millisecond {
		return fmt.Sprintf("%.0fµs", float64(d.Microseconds()))
	}
	if d < time.Second {
		return fmt.Sprintf("%.1fms", float64(d.Microseconds())/1000)
	}
	return fmt.Sprintf("%.2fs", d.Seconds())
}

func renderHistogram(latencies []time.Duration, width int) string {
	if len(latencies) == 0 {
		return ""
	}

	// Create 10 buckets
	buckets := 10
	sorted := make([]time.Duration, len(latencies))
	copy(sorted, latencies)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	minVal := sorted[0]
	maxVal := sorted[len(sorted)-1]
	span := maxVal - minVal
	if span == 0 {
		span = 1
	}

	counts := make([]int, buckets)
	for _, l := range sorted {
		bucket := int(float64(l-minVal) / float64(span) * float64(buckets-1))
		if bucket >= buckets {
			bucket = buckets - 1
		}
		counts[bucket]++
	}

	maxCount := 0
	for _, c := range counts {
		if c > maxCount {
			maxCount = c
		}
	}

	var lines []string
	barChars := "▏▎▍▌▋▊▉█"
	_ = barChars

	for i, c := range counts {
		bucketStart := minVal + time.Duration(float64(span)*float64(i)/float64(buckets))
		label := formatDuration(bucketStart)
		barLen := 0
		if maxCount > 0 {
			barLen = c * width / maxCount
		}
		bar := strings.Repeat("█", barLen)
		barStyle := lipgloss.NewStyle().Foreground(ColorSecondary)
		lines = append(lines, fmt.Sprintf("  %8s │%s %d", label, barStyle.Render(bar), c))
	}

	return strings.Join(lines, "\n")
}
