package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/charmbracelet/huh"
)

// ─── Generate Wizard Result ─────────────────────────────────────────────────────

// GenerateResult contains all answers from the interactive generate wizard.
type GenerateResult struct {
	// General
	ProjectName string
	ListenAddr  string
	Profile     string

	// TLS
	EnableTLS bool
	TLSCert   string
	TLSKey    string
	TLSMinVer string

	// Security
	EnableSSRF bool

	// KMS
	KMSProvider string

	// Routes (first route — user can add more manually)
	Routes []GenerateRoute

	// Rate limit backend
	RateLimitBackend string

	// JWT
	EnableJWT bool
	JWKSURL   string

	// Resilience
	EnableCircuitBreaker bool
	CBFailureThreshold   string
	CBTimeout            string

	EnableRetry   bool
	RetryAttempts string

	// Coordinator
	EnableCoordinator  bool
	CoordinatorAddress string

	// Redis (used by rate limiting or other policies)
	RedisAddress  string
	RedisPassword string

	// Docker Compose
	GenerateCompose    bool
	IncludeRedis       bool
	IncludePostgres    bool
	PostgresPassword   string
	IncludeCoordinator bool
	RouterPort         string
	CoordinatorPort    string
	MetricsPort        string

	// Output
	OutputDir string
	Force     bool
}

// GenerateRoute holds a single route definition from the wizard.
type GenerateRoute struct {
	Path      string
	Method    string
	TargetURL string
	RPS       string
	Burst     string
	MaxWait   string
}

// ─── Wizard ─────────────────────────────────────────────────────────────────────

// RunGenerateWizard runs the interactive config + docker-compose generator.
func RunGenerateWizard() (*GenerateResult, error) {
	r := &GenerateResult{
		ListenAddr:  ":8080",
		TLSMinVer:   "1.3",
		RouterPort:  "8080",
		MetricsPort: "9100",
		OutputDir:   ".",
	}

	route := GenerateRoute{
		Method:  "get",
		RPS:     "10",
		Burst:   "20",
		MaxWait: "5s",
	}

	cwd, _ := os.Getwd()
	defaultName := filepath.Base(cwd)

	// ─── Page 1: Project Basics ─────────────────────────────────────────────────

	form1 := huh.NewForm(
		huh.NewGroup(
			huh.NewNote().
				Title("  CSAR Config Generator").
				Description("Interactive wizard to generate config.yaml and docker-compose.yaml.\n"+
					"Answer the questions below to create a ready-to-use configuration."),

			huh.NewInput().
				Title("Project name").
				Description("Used for logging, comments, and container labels").
				Value(&r.ProjectName).
				Placeholder(defaultName).
				Validate(func(s string) error {
					if strings.TrimSpace(s) == "" {
						r.ProjectName = defaultName
					}
					return nil
				}),

			huh.NewInput().
				Title("Listen address").
				Description("Address the router will bind to (host:port)").
				Value(&r.ListenAddr).
				Placeholder(":8080"),

			huh.NewSelect[string]().
				Title("Deployment profile").
				Description("Determines security constraints and infrastructure").
				Options(
					huh.NewOption("Dev Local — no TLS, no coordinator, relaxed security", "dev-local"),
					huh.NewOption("Prod Single — single node, TLS required", "prod-single"),
					huh.NewOption("Prod Distributed — multi-node with coordinator", "prod-distributed"),
				).
				Value(&r.Profile),
		),
	).WithTheme(huh.ThemeCatppuccin())

	if err := form1.Run(); err != nil {
		return nil, err
	}

	// Pre-fill based on profile
	isProd := r.Profile == "prod-single" || r.Profile == "prod-distributed"
	if isProd {
		r.EnableTLS = true
		r.EnableSSRF = true
	}
	if r.Profile == "prod-distributed" {
		r.EnableCoordinator = true
	}

	// ─── Page 2: Security & TLS ─────────────────────────────────────────────────

	form2 := huh.NewForm(
		// Always-visible security group
		huh.NewGroup(
			huh.NewNote().
				Title("  Security & TLS"),

			huh.NewConfirm().
				Title("Enable TLS?").
				Description("HTTPS for inbound connections (required for production)").
				Value(&r.EnableTLS),
		),
		// TLS details — shown only when TLS is enabled
		huh.NewGroup(
			huh.NewInput().
				Title("TLS certificate file").
				Description("Path to PEM-encoded server certificate").
				Value(&r.TLSCert).
				Placeholder("/etc/csar/tls/server-cert.pem"),

			huh.NewInput().
				Title("TLS key file").
				Description("Path to PEM-encoded private key").
				Value(&r.TLSKey).
				Placeholder("/etc/csar/tls/server-key.pem"),

			huh.NewSelect[string]().
				Title("Minimum TLS version").
				Options(
					huh.NewOption("TLS 1.3 (recommended)", "1.3"),
					huh.NewOption("TLS 1.2", "1.2"),
				).
				Value(&r.TLSMinVer),
		).WithHideFunc(func() bool { return !r.EnableTLS }),

		// SSRF & KMS
		huh.NewGroup(
			huh.NewConfirm().
				Title("Enable SSRF protection?").
				Description("Block outbound connections to private/loopback/metadata IPs").
				Value(&r.EnableSSRF),

			huh.NewSelect[string]().
				Title("KMS provider").
				Description("Key Management Service for token encryption").
				Options(
					huh.NewOption("Local — in-memory keys (dev only)", "local"),
					huh.NewOption("Yandex Cloud KMS", "yandexapi"),
				).
				Value(&r.KMSProvider),
		),
	).WithTheme(huh.ThemeCatppuccin())

	if err := form2.Run(); err != nil {
		return nil, err
	}

	// ─── Page 3: First Route ────────────────────────────────────────────────────

	form3 := huh.NewForm(
		huh.NewGroup(
			huh.NewNote().
				Title("  Your First Route").
				Description("Configure the primary API route.\nYou can add more routes later by editing config.yaml."),

			huh.NewInput().
				Title("Route path").
				Description("URL path the gateway will handle").
				Value(&route.Path).
				Placeholder("/api/v1/example").
				Validate(func(s string) error {
					if s != "" && !strings.HasPrefix(s, "/") {
						return fmt.Errorf("path must start with /")
					}
					return nil
				}),

			huh.NewSelect[string]().
				Title("HTTP method").
				Options(
					huh.NewOption("GET", "get"),
					huh.NewOption("POST", "post"),
					huh.NewOption("PUT", "put"),
					huh.NewOption("DELETE", "delete"),
					huh.NewOption("PATCH", "patch"),
				).
				Value(&route.Method),

			huh.NewInput().
				Title("Backend target URL").
				Description("Upstream service URL to proxy requests to").
				Value(&route.TargetURL).
				Placeholder("http://localhost:3000/api/v1/example").
				Validate(func(s string) error {
					if s != "" && !strings.HasPrefix(s, "http://") && !strings.HasPrefix(s, "https://") {
						return fmt.Errorf("target URL must start with http:// or https://")
					}
					return nil
				}),
		),
	).WithTheme(huh.ThemeCatppuccin())

	if err := form3.Run(); err != nil {
		return nil, err
	}

	// ─── Page 4: Route Middleware ────────────────────────────────────────────────

	form4 := huh.NewForm(
		huh.NewGroup(
			huh.NewNote().
				Title("  Rate Limiting"),

			huh.NewSelect[string]().
				Title("Rate limiting backend").
				Description("Where to store rate limit counters").
				Options(
					huh.NewOption("Local — in-memory per pod (simplest)", "local"),
					huh.NewOption("Redis — distributed across all pods", "redis"),
					huh.NewOption("Coordinator — dynamic quota allocation", "coordinator"),
				).
				Value(&r.RateLimitBackend),

			huh.NewInput().
				Title("Requests per second (RPS)").
				Description("Maximum sustained request rate").
				Value(&route.RPS).
				Placeholder("10").
				Validate(validatePositiveFloat),

			huh.NewInput().
				Title("Burst size").
				Description("Maximum burst capacity above RPS").
				Value(&route.Burst).
				Placeholder("20").
				Validate(validatePositiveInt),

			huh.NewInput().
				Title("Max wait duration").
				Description("How long a throttled request waits before rejection").
				Value(&route.MaxWait).
				Placeholder("5s"),
		),

		// JWT
		huh.NewGroup(
			huh.NewNote().
				Title("  Authentication & Resilience"),

			huh.NewConfirm().
				Title("Enable JWT authentication?").
				Description("Validate inbound Bearer tokens against a JWKS endpoint").
				Value(&r.EnableJWT),
		),
		// JWKS URL — conditional on JWT
		huh.NewGroup(
			huh.NewInput().
				Title("JWKS URL").
				Description("URL to fetch JSON Web Key Set from").
				Value(&r.JWKSURL).
				Placeholder("https://auth.example.com/.well-known/jwks.json"),
		).WithHideFunc(func() bool { return !r.EnableJWT }),

		// Circuit breaker toggle
		huh.NewGroup(
			huh.NewConfirm().
				Title("Enable circuit breaker?").
				Description("Trip on consecutive failures to protect upstream").
				Value(&r.EnableCircuitBreaker),
		),
		// Circuit breaker details — conditional
		huh.NewGroup(
			huh.NewInput().
				Title("Circuit breaker failure threshold").
				Description("Number of consecutive failures to trip the breaker").
				Value(&r.CBFailureThreshold).
				Placeholder("3").
				Validate(validatePositiveInt),

			huh.NewInput().
				Title("Circuit breaker timeout").
				Description("How long the breaker stays open before probing").
				Value(&r.CBTimeout).
				Placeholder("30s"),
		).WithHideFunc(func() bool { return !r.EnableCircuitBreaker }),

		// Retry toggle
		huh.NewGroup(
			huh.NewConfirm().
				Title("Enable retry?").
				Description("Automatically retry on transient upstream failures").
				Value(&r.EnableRetry),
		),
		// Retry details — conditional
		huh.NewGroup(
			huh.NewInput().
				Title("Max retry attempts").
				Value(&r.RetryAttempts).
				Placeholder("3").
				Validate(validatePositiveInt),
		).WithHideFunc(func() bool { return !r.EnableRetry }),
	).WithTheme(huh.ThemeCatppuccin())

	if err := form4.Run(); err != nil {
		return nil, err
	}

	// ─── Page 5a: Redis connection (if needed by rate-limit backend) ─────────────

	needsRedis := r.RateLimitBackend == "redis"
	if needsRedis {
		formRedis := huh.NewForm(
			huh.NewGroup(
				huh.NewNote().
					Title("  Redis Connection").
					Description("Rate limiting backend \"redis\" requires a Redis connection."),

				huh.NewInput().
					Title("Redis address").
					Description("host:port of the Redis server").
					Value(&r.RedisAddress).
					Placeholder("redis:6379"),

				huh.NewInput().
					Title("Redis password (optional)").
					Description("Leave empty if Redis has no AUTH configured").
					Value(&r.RedisPassword).
					Placeholder(""),
			),
		).WithTheme(huh.ThemeCatppuccin())

		if err := formRedis.Run(); err != nil {
			return nil, err
		}
	}

	// ─── Page 5b: Coordinator ───────────────────────────────────────────────────
	// If rate-limit backend is "coordinator" or profile is "prod-distributed",
	// coordinator is required — no need to ask.
	if r.RateLimitBackend == "coordinator" || r.Profile == "prod-distributed" {
		r.EnableCoordinator = true
	}

	// Only ask about coordinator if it hasn't been auto-determined
	if !r.EnableCoordinator {
		form5 := huh.NewForm(
			huh.NewGroup(
				huh.NewNote().
					Title("  Coordinator"),

				huh.NewConfirm().
					Title("Enable coordinator?").
					Description("CSAR control plane for multi-node deployments").
					Value(&r.EnableCoordinator),
			),
		).WithTheme(huh.ThemeCatppuccin())

		if err := form5.Run(); err != nil {
			return nil, err
		}
	}

	// Ask for coordinator address if enabled (regardless of how it was enabled)
	if r.EnableCoordinator {
		coordDesc := "Specify the gRPC address of the coordinator."
		if r.RateLimitBackend == "coordinator" {
			coordDesc = "Rate limiting backend \"coordinator\" requires a coordinator.\n" + coordDesc
		}

		form5addr := huh.NewForm(
			huh.NewGroup(
				huh.NewNote().
					Title("  Coordinator").
					Description(coordDesc),

				huh.NewInput().
					Title("Coordinator address").
					Description("gRPC address of the coordinator service").
					Value(&r.CoordinatorAddress).
					Placeholder("coordinator:9090"),
			),
		).WithTheme(huh.ThemeCatppuccin())

		if err := form5addr.Run(); err != nil {
			return nil, err
		}
	}

	// ─── Page 6: Docker Compose ─────────────────────────────────────────────────

	// If coordinator is required by config, pre-set it so compose stays
	// consistent with config.yaml — don't let the user exclude it.
	coordinatorRequired := r.EnableCoordinator

	// If coordinator is required, auto-include its compose service.
	if coordinatorRequired {
		r.IncludeCoordinator = true
	}

	form6 := huh.NewForm(
		huh.NewGroup(
			huh.NewNote().
				Title("  Docker Compose").
				Description("Generate a docker-compose.yaml to run the full stack locally."),

			huh.NewConfirm().
				Title("Generate docker-compose.yaml?").
				Description("Create a Docker Compose file alongside the config").
				Value(&r.GenerateCompose),
		),
		// Compose details — shown only when GenerateCompose is true
		huh.NewGroup(
			huh.NewInput().
				Title("Router port (host)").
				Description("Port to expose the router on the host").
				Value(&r.RouterPort).
				Placeholder("8080"),

			huh.NewInput().
				Title("Metrics port (host)").
				Description("Port to expose Prometheus metrics").
				Value(&r.MetricsPort).
				Placeholder("9100"),
		).WithHideFunc(func() bool { return !r.GenerateCompose }),

		// Redis container
		huh.NewGroup(
			huh.NewConfirm().
				Title("Include Redis container?").
				Description("Adds a Redis service to docker-compose").
				Value(&r.IncludeRedis),
		).WithHideFunc(func() bool { return !r.GenerateCompose }),

		// PostgreSQL container
		huh.NewGroup(
			huh.NewConfirm().
				Title("Include PostgreSQL container?").
				Description("Adds a PostgreSQL service to docker-compose").
				Value(&r.IncludePostgres),
		).WithHideFunc(func() bool { return !r.GenerateCompose }),

		// PostgreSQL password
		huh.NewGroup(
			huh.NewInput().
				Title("PostgreSQL password").
				Value(&r.PostgresPassword).
				Placeholder("csar_dev"),
		).WithHideFunc(func() bool { return !r.GenerateCompose || !r.IncludePostgres }),

		// Coordinator container — only ask if it's not already required by config.
		// When required, it is auto-included and this question is skipped.
		huh.NewGroup(
			huh.NewConfirm().
				Title("Include coordinator container?").
				Description("Adds the CSAR coordinator service to docker-compose").
				Value(&r.IncludeCoordinator),
		).WithHideFunc(func() bool { return !r.GenerateCompose || coordinatorRequired }),

		// Coordinator port
		huh.NewGroup(
			huh.NewInput().
				Title("Coordinator port (host)").
				Value(&r.CoordinatorPort).
				Placeholder("9090"),
		).WithHideFunc(func() bool { return !r.GenerateCompose || !r.IncludeCoordinator }),
	).WithTheme(huh.ThemeCatppuccin())

	if err := form6.Run(); err != nil {
		return nil, err
	}

	// If Redis was needed for config but user didn't include the container,
	// and no address was set yet, ask for the external Redis address.
	if needsRedis && !r.IncludeRedis && r.RedisAddress == "" {
		formRedisExt := huh.NewForm(
			huh.NewGroup(
				huh.NewNote().
					Title("  External Redis").
					Description("You chose Redis rate limiting but no Redis container.\nSpecify your external Redis address."),

				huh.NewInput().
					Title("Redis address").
					Value(&r.RedisAddress).
					Placeholder("redis.example.com:6379"),

				huh.NewInput().
					Title("Redis password (optional)").
					Value(&r.RedisPassword).
					Placeholder(""),
			),
		).WithTheme(huh.ThemeCatppuccin())

		if err := formRedisExt.Run(); err != nil {
			return nil, err
		}
	}

	// ─── Page 7: Output ─────────────────────────────────────────────────────────

	form7 := huh.NewForm(
		huh.NewGroup(
			huh.NewNote().
				Title("  Output"),

			huh.NewInput().
				Title("Output directory").
				Description("Where to write the generated files").
				Value(&r.OutputDir).
				Placeholder("."),

			huh.NewConfirm().
				Title("Overwrite existing files?").
				Value(&r.Force),
		),
	).WithTheme(huh.ThemeCatppuccin())

	if err := form7.Run(); err != nil {
		return nil, err
	}

	// ─── Apply defaults ─────────────────────────────────────────────────────────

	if r.ProjectName == "" {
		r.ProjectName = defaultName
	}
	if r.ListenAddr == "" {
		r.ListenAddr = ":8080"
	}
	if r.OutputDir == "" {
		r.OutputDir = "."
	}
	if route.Path == "" {
		route.Path = "/api/v1/example"
	}
	if route.TargetURL == "" {
		route.TargetURL = "http://localhost:3000" + route.Path
	}
	if route.RPS == "" {
		route.RPS = "10"
	}
	if route.Burst == "" {
		route.Burst = "20"
	}
	if route.MaxWait == "" {
		route.MaxWait = "5s"
	}
	if r.RouterPort == "" {
		r.RouterPort = "8080"
	}
	if r.MetricsPort == "" {
		r.MetricsPort = "9100"
	}
	if r.CoordinatorPort == "" {
		r.CoordinatorPort = "9090"
	}
	if r.RedisAddress == "" && r.RateLimitBackend == "redis" {
		r.RedisAddress = "redis:6379"
	}
	if r.PostgresPassword == "" {
		r.PostgresPassword = "csar_dev"
	}
	if r.CoordinatorAddress == "" && r.EnableCoordinator {
		r.CoordinatorAddress = "coordinator:9090"
	}
	if r.CBFailureThreshold == "" {
		r.CBFailureThreshold = "3"
	}
	if r.CBTimeout == "" {
		r.CBTimeout = "30s"
	}
	if r.RetryAttempts == "" {
		r.RetryAttempts = "3"
	}
	if r.TLSCert == "" && r.EnableTLS {
		r.TLSCert = "/etc/csar/tls/server-cert.pem"
	}
	if r.TLSKey == "" && r.EnableTLS {
		r.TLSKey = "/etc/csar/tls/server-key.pem"
	}

	r.Routes = []GenerateRoute{route}

	return r, nil
}

// ─── Validators ─────────────────────────────────────────────────────────────────

func validatePositiveFloat(s string) error {
	if s == "" {
		return nil
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return fmt.Errorf("must be a number")
	}
	if v <= 0 {
		return fmt.Errorf("must be positive")
	}
	return nil
}

func validatePositiveInt(s string) error {
	if s == "" {
		return nil
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return fmt.Errorf("must be an integer")
	}
	if v <= 0 {
		return fmt.Errorf("must be positive")
	}
	return nil
}

// ─── Render helpers ─────────────────────────────────────────────────────────────

func floatOrDefault(s, def string) string {
	if s == "" {
		return def
	}
	if !strings.Contains(s, ".") {
		return s + ".0"
	}
	return s
}

func intOrDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func portOrDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
