package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"
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

// ─── Apply Result ───────────────────────────────────────────────────────────────

// generatedFile is a file to be written atomically alongside others.
type generatedFile struct {
	path    string
	content string
}

// ApplyGenerateResult writes the generated config.yaml and (optionally)
// docker-compose.yaml to disk, then prints a summary.
//
// The write is atomic: all files are rendered and pre-flight checked for
// existing-file conflicts *before* any bytes are written. This prevents
// partial output where some files are written but others fail.
func ApplyGenerateResult(r *GenerateResult) error {
	outDir := r.OutputDir
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("creating output directory: %w", err)
	}

	// Phase 1: Render all content up-front.
	files := []generatedFile{
		{path: filepath.Join(outDir, "config.yaml"), content: renderConfigYAML(r)},
		{path: filepath.Join(outDir, ".env.example"), content: renderEnvExample(r)},
	}
	if r.GenerateCompose {
		files = append(files, generatedFile{
			path:    filepath.Join(outDir, "docker-compose.yaml"),
			content: renderDockerCompose(r),
		})
	}

	// Phase 2: Pre-flight — check that no target file exists (unless --force).
	if !r.Force {
		var conflicts []string
		for _, f := range files {
			if _, err := os.Stat(f.path); err == nil {
				conflicts = append(conflicts, f.path)
			}
		}
		if len(conflicts) > 0 {
			return fmt.Errorf(
				"refusing to overwrite existing file(s): %s; use --force to overwrite",
				strings.Join(conflicts, ", "),
			)
		}
	}

	// Phase 3: Write all files — no conflict check remains so partial
	// failure here is an OS-level I/O error, not a user-input issue.
	for _, f := range files {
		if err := os.WriteFile(f.path, []byte(f.content), 0o644); err != nil {
			return fmt.Errorf("writing %s: %w", f.path, err)
		}
		fmt.Printf("  %s created: %s\n", IconCheck, f.path)
	}

	// Print summary
	printGenerateSummary(r)
	return nil
}

// ─── Config YAML Renderer ───────────────────────────────────────────────────────

func renderConfigYAML(r *GenerateResult) string {
	var b strings.Builder

	b.WriteString(fmt.Sprintf("# CSAR Configuration — %s\n", r.ProjectName))
	b.WriteString(fmt.Sprintf("# Profile: %s\n", r.Profile))
	b.WriteString("# Generated by: csar-helper generate\n\n")

	b.WriteString(fmt.Sprintf("profile: %s\n\n", r.Profile))
	b.WriteString(fmt.Sprintf("listen_addr: %q\n\n", r.ListenAddr))

	// TLS
	if r.EnableTLS {
		b.WriteString("tls:\n")
		b.WriteString(fmt.Sprintf("  cert_file: %q\n", r.TLSCert))
		b.WriteString(fmt.Sprintf("  key_file: %q\n", r.TLSKey))
		b.WriteString(fmt.Sprintf("  min_version: %q\n", r.TLSMinVer))
		b.WriteString("  # Uncomment for mTLS:\n")
		b.WriteString("  # client_ca_file: \"/etc/csar/tls/client-ca.pem\"\n\n")
	}

	// Security policy
	isProd := r.Profile == "prod-single" || r.Profile == "prod-distributed"
	if isProd {
		b.WriteString("security_policy:\n")
		b.WriteString("  environment: \"prod\"\n")
		b.WriteString("  forbid_insecure_in_prod: true\n")
		b.WriteString("  redact_sensitive_logs: true\n")
		if r.Profile == "prod-distributed" {
			b.WriteString("  require_mtls_for_coordinator: true\n")
		}
		b.WriteString("\n")
	}

	// SSRF
	if r.EnableSSRF {
		b.WriteString("ssrf_protection:\n")
		b.WriteString("  block_private: true\n")
		b.WriteString("  block_loopback: true\n")
		b.WriteString("  block_link_local: true\n")
		b.WriteString("  block_metadata: true\n\n")
	}

	// KMS
	if r.KMSProvider != "" {
		b.WriteString("kms:\n")
		b.WriteString(fmt.Sprintf("  provider: %q\n", r.KMSProvider))
		if r.KMSProvider != "local" {
			b.WriteString("  cache:\n")
			b.WriteString("    enabled: true\n")
			b.WriteString("    ttl: \"60s\"\n")
			b.WriteString("    max_entries: 10000\n")
		} else {
			b.WriteString("  # Configure keys inline or via CLI flags:\n")
			b.WriteString("  # local_keys:\n")
			b.WriteString("  #   dev-key: \"dev-passphrase\"\n")
		}
		b.WriteString("\n")
	}

	// Redis
	if r.RateLimitBackend == "redis" {
		addr := r.RedisAddress
		if addr == "" {
			addr = "redis:6379"
		}
		b.WriteString("redis:\n")
		b.WriteString(fmt.Sprintf("  address: %q\n", addr))
		if r.RedisPassword != "" {
			b.WriteString(fmt.Sprintf("  password: %q\n", r.RedisPassword))
		}
		b.WriteString("  key_prefix: \"csar:rl:\"\n\n")
	}

	// Coordinator
	b.WriteString("coordinator:\n")
	b.WriteString(fmt.Sprintf("  enabled: %t\n", r.EnableCoordinator))
	if r.EnableCoordinator {
		b.WriteString(fmt.Sprintf("  address: %q\n", r.CoordinatorAddress))
		if isProd {
			b.WriteString("  ca_file: \"${CSAR_COORDINATOR_CA_FILE}\"\n")
			b.WriteString("  cert_file: \"${CSAR_COORDINATOR_CERT_FILE}\"\n")
			b.WriteString("  key_file: \"${CSAR_COORDINATOR_KEY_FILE}\"\n")
		} else {
			b.WriteString("  allow_insecure: true\n")
		}
	}
	b.WriteString("\n")

	// Circuit breakers
	if r.EnableCircuitBreaker {
		b.WriteString("circuit_breakers:\n")
		b.WriteString("  standard:\n")
		b.WriteString("    max_requests: 5\n")
		b.WriteString("    interval: \"60s\"\n")
		b.WriteString(fmt.Sprintf("    timeout: %q\n", r.CBTimeout))
		b.WriteString(fmt.Sprintf("    failure_threshold: %s\n", r.CBFailureThreshold))
		b.WriteString("\n")
	}

	// Paths
	b.WriteString("paths:\n")
	for _, route := range r.Routes {
		b.WriteString(fmt.Sprintf("  %s:\n", route.Path))
		b.WriteString(fmt.Sprintf("    %s:\n", route.Method))
		b.WriteString("      x-csar-backend:\n")
		b.WriteString(fmt.Sprintf("        target_url: %q\n", route.TargetURL))

		// JWT
		if r.EnableJWT && r.JWKSURL != "" {
			b.WriteString("      x-csar-auth-validate:\n")
			b.WriteString(fmt.Sprintf("        jwks_url: %q\n", r.JWKSURL))
			b.WriteString("        # issuer: \"https://auth.example.com/\"\n")
			b.WriteString("        # audiences:\n")
			b.WriteString("        #   - \"my-api\"\n")
		}

		// Security placeholder
		b.WriteString("      # x-csar-security:\n")
		b.WriteString("      #   kms_key_id: \"your-key-id\"\n")
		b.WriteString("      #   token_ref: \"api_token\"\n")
		b.WriteString("      #   inject_header: \"Authorization\"\n")
		b.WriteString("      #   inject_format: \"Bearer {token}\"\n")

		// Traffic
		b.WriteString("      x-csar-traffic:\n")
		b.WriteString(fmt.Sprintf("        rps: %s\n", floatOrDefault(route.RPS, "10.0")))
		b.WriteString(fmt.Sprintf("        burst: %s\n", intOrDefault(route.Burst, "20")))
		b.WriteString(fmt.Sprintf("        max_wait: %q\n", route.MaxWait))
		if r.RateLimitBackend != "local" && r.RateLimitBackend != "" {
			b.WriteString(fmt.Sprintf("        backend: %q\n", r.RateLimitBackend))
		}

		// Resilience
		if r.EnableCircuitBreaker {
			b.WriteString("      x-csar-resilience:\n")
			b.WriteString("        circuit_breaker: \"standard\"\n")
		}

		// Retry
		if r.EnableRetry {
			b.WriteString("      x-csar-retry:\n")
			b.WriteString(fmt.Sprintf("        max_attempts: %s\n", intOrDefault(r.RetryAttempts, "3")))
			b.WriteString("        backoff: \"1s\"\n")
			b.WriteString("        max_backoff: \"10s\"\n")
		}
	}

	// Health endpoint
	b.WriteString("\n  /health:\n")
	b.WriteString("    get:\n")
	b.WriteString("      x-csar-backend:\n")
	b.WriteString("        target_url: \"http://localhost:8080\"\n")

	return b.String()
}

// ─── Docker Compose Renderer ────────────────────────────────────────────────────

func renderDockerCompose(r *GenerateResult) string {
	var b strings.Builder

	b.WriteString(fmt.Sprintf("# Docker Compose — %s\n", r.ProjectName))
	b.WriteString("# Generated by: csar-helper generate\n")
	b.WriteString("#\n")
	b.WriteString("# Usage:\n")
	b.WriteString("#   cp .env.example .env   # fill in real values\n")
	b.WriteString("#   docker compose up -d\n\n")

	b.WriteString("services:\n")

	// ─── Coordinator ────────────────────────────────────────────────────────────
	if r.IncludeCoordinator {
		coordPort := portOrDefault(r.CoordinatorPort, "9090")
		b.WriteString("  coordinator:\n")
		b.WriteString("    image: csar-coordinator:latest\n")
		b.WriteString("    container_name: csar-coordinator\n")
		b.WriteString("    restart: unless-stopped\n")
		b.WriteString("    ports:\n")
		b.WriteString(fmt.Sprintf("      - \"%s:9090\"\n", coordPort))
		b.WriteString("    environment:\n")
		b.WriteString("      - CSAR_TOKEN_STORE_DSN=${CSAR_TOKEN_STORE_DSN}\n")
		if r.EnableTLS {
			b.WriteString("    volumes:\n")
			b.WriteString("      - ./tls:/etc/csar/tls:ro\n")
			b.WriteString("    command: >\n")
			b.WriteString("      -listen :9090\n")
			b.WriteString("      -token-store postgres\n")
			b.WriteString("      -token-store-dsn ${CSAR_TOKEN_STORE_DSN}\n")
			b.WriteString("      -tls-cert /etc/csar/tls/coordinator-cert.pem\n")
			b.WriteString("      -tls-key /etc/csar/tls/coordinator-key.pem\n")
			b.WriteString("      -tls-ca /etc/csar/tls/ca.pem\n")
		} else {
			b.WriteString("    command: >\n")
			b.WriteString("      -listen :9090\n")
			b.WriteString("      -token-store postgres\n")
			b.WriteString("      -token-store-dsn ${CSAR_TOKEN_STORE_DSN}\n")
		}
		if r.IncludePostgres {
			b.WriteString("    depends_on:\n")
			b.WriteString("      postgres:\n")
			b.WriteString("        condition: service_healthy\n")
		}
		b.WriteString("    networks:\n")
		b.WriteString("      - csar\n")
		b.WriteString("\n")
	}

	// ─── Router ─────────────────────────────────────────────────────────────────
	routerPort := portOrDefault(r.RouterPort, "8080")
	metricsPort := portOrDefault(r.MetricsPort, "9100")

	b.WriteString("  router:\n")
	b.WriteString("    image: csar:latest\n")
	b.WriteString("    container_name: csar-router\n")
	b.WriteString("    restart: unless-stopped\n")
	b.WriteString("    ports:\n")
	b.WriteString(fmt.Sprintf("      - \"%s:8080\"\n", routerPort))
	b.WriteString(fmt.Sprintf("      - \"%s:9100\"\n", metricsPort))

	// depends_on
	var deps []string
	if r.IncludeCoordinator {
		deps = append(deps, "coordinator")
	}
	if r.IncludeRedis {
		deps = append(deps, "redis")
	}
	if len(deps) > 0 {
		b.WriteString("    depends_on:\n")
		for _, dep := range deps {
			b.WriteString(fmt.Sprintf("      - %s\n", dep))
		}
	}

	b.WriteString("    volumes:\n")
	b.WriteString("      - ./config.yaml:/etc/csar/config.yaml:ro\n")
	if r.EnableTLS {
		b.WriteString("      - ./tls:/etc/csar/tls:ro\n")
	}
	b.WriteString("    environment:\n")
	b.WriteString("      - CSAR_KMS_PROVIDER=${CSAR_KMS_PROVIDER:-local}\n")
	if r.KMSProvider == "local" {
		b.WriteString("      - CSAR_KMS_LOCAL_KEYS=${CSAR_KMS_LOCAL_KEYS:-dev-key=dev-passphrase}\n")
	}
	b.WriteString("    command: >\n")
	b.WriteString("      -config /etc/csar/config.yaml\n")
	b.WriteString("      -kms-provider ${CSAR_KMS_PROVIDER:-local}\n")
	b.WriteString("      -metrics-addr :9100\n")
	b.WriteString("    healthcheck:\n")
	b.WriteString("      test: [\"CMD\", \"wget\", \"-q\", \"--spider\", \"http://localhost:8080/health\"]\n")
	b.WriteString("      interval: 10s\n")
	b.WriteString("      timeout: 3s\n")
	b.WriteString("      retries: 3\n")
	b.WriteString("    networks:\n")
	b.WriteString("      - csar\n")
	b.WriteString("\n")

	// ─── Redis ──────────────────────────────────────────────────────────────────
	if r.IncludeRedis {
		b.WriteString("  redis:\n")
		b.WriteString("    image: redis:7-alpine\n")
		b.WriteString("    container_name: csar-redis\n")
		b.WriteString("    restart: unless-stopped\n")
		b.WriteString("    ports:\n")
		b.WriteString("      - \"6379:6379\"\n")
		if r.RedisPassword != "" {
			b.WriteString(fmt.Sprintf("    command: redis-server --requirepass ${REDIS_PASSWORD:-%s} --maxmemory 128mb --maxmemory-policy allkeys-lru\n", r.RedisPassword))
		} else {
			b.WriteString("    command: redis-server --maxmemory 128mb --maxmemory-policy allkeys-lru\n")
		}
		b.WriteString("    healthcheck:\n")
		if r.RedisPassword != "" {
			b.WriteString("      test: [\"CMD\", \"redis-cli\", \"-a\", \"${REDIS_PASSWORD}\", \"ping\"]\n")
		} else {
			b.WriteString("      test: [\"CMD\", \"redis-cli\", \"ping\"]\n")
		}
		b.WriteString("      interval: 10s\n")
		b.WriteString("      timeout: 3s\n")
		b.WriteString("      retries: 3\n")
		b.WriteString("    networks:\n")
		b.WriteString("      - csar\n")
		b.WriteString("\n")
	}

	// ─── PostgreSQL ─────────────────────────────────────────────────────────────
	if r.IncludePostgres {
		pgPass := r.PostgresPassword
		if pgPass == "" {
			pgPass = "csar_dev"
		}
		b.WriteString("  postgres:\n")
		b.WriteString("    image: postgres:16-alpine\n")
		b.WriteString("    container_name: csar-postgres\n")
		b.WriteString("    restart: unless-stopped\n")
		b.WriteString("    environment:\n")
		b.WriteString("      POSTGRES_DB: csar\n")
		b.WriteString("      POSTGRES_USER: csar\n")
		b.WriteString(fmt.Sprintf("      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:-%s}\n", pgPass))
		b.WriteString("    ports:\n")
		b.WriteString("      - \"5432:5432\"\n")
		b.WriteString("    volumes:\n")
		b.WriteString("      - pgdata:/var/lib/postgresql/data\n")
		b.WriteString("    healthcheck:\n")
		b.WriteString("      test: [\"CMD-SHELL\", \"pg_isready -U csar\"]\n")
		b.WriteString("      interval: 10s\n")
		b.WriteString("      timeout: 3s\n")
		b.WriteString("      retries: 5\n")
		b.WriteString("    networks:\n")
		b.WriteString("      - csar\n")
		b.WriteString("\n")
	}

	// ─── Volumes ────────────────────────────────────────────────────────────────
	if r.IncludePostgres {
		b.WriteString("volumes:\n")
		b.WriteString("  pgdata:\n\n")
	}

	// ─── Networks ───────────────────────────────────────────────────────────────
	b.WriteString("networks:\n")
	b.WriteString("  csar:\n")
	b.WriteString("    driver: bridge\n")

	return b.String()
}

// ─── Env Example Renderer ───────────────────────────────────────────────────────

func renderEnvExample(r *GenerateResult) string {
	var b strings.Builder

	b.WriteString(fmt.Sprintf("# CSAR Environment Variables — %s\n", r.ProjectName))
	b.WriteString(fmt.Sprintf("# Profile: %s\n", r.Profile))
	b.WriteString("# Generated by: csar-helper generate\n")
	b.WriteString("# Copy to .env and fill in real values.\n\n")

	// TLS
	if r.EnableTLS {
		b.WriteString("# TLS certificates\n")
		b.WriteString(fmt.Sprintf("CSAR_TLS_CERT_FILE=%s\n", r.TLSCert))
		b.WriteString(fmt.Sprintf("CSAR_TLS_KEY_FILE=%s\n", r.TLSKey))
		b.WriteString("\n")
	}

	// KMS
	b.WriteString("# KMS provider\n")
	b.WriteString(fmt.Sprintf("CSAR_KMS_PROVIDER=%s\n", r.KMSProvider))
	if r.KMSProvider == "local" {
		b.WriteString("CSAR_KMS_LOCAL_KEYS=dev-key=dev-passphrase\n")
	} else {
		b.WriteString("CSAR_KMS_KEY_ID=your-kms-key-id\n")
	}
	b.WriteString("\n")

	// Coordinator
	if r.EnableCoordinator {
		b.WriteString("# Coordinator connection (gRPC)\n")
		b.WriteString(fmt.Sprintf("CSAR_COORDINATOR_ADDRESS=%s\n", r.CoordinatorAddress))
		isProd := r.Profile == "prod-single" || r.Profile == "prod-distributed"
		if isProd {
			b.WriteString("CSAR_COORDINATOR_CA_FILE=/etc/csar/tls/coordinator-ca.pem\n")
			b.WriteString("CSAR_COORDINATOR_CERT_FILE=/etc/csar/tls/router-client-cert.pem\n")
			b.WriteString("CSAR_COORDINATOR_KEY_FILE=/etc/csar/tls/router-client-key.pem\n")
		}
		b.WriteString("\n")
	}

	// Redis
	if r.RateLimitBackend == "redis" {
		b.WriteString("# Redis\n")
		b.WriteString(fmt.Sprintf("REDIS_ADDRESS=%s\n", r.RedisAddress))
		if r.RedisPassword != "" {
			b.WriteString(fmt.Sprintf("REDIS_PASSWORD=%s\n", r.RedisPassword))
		} else {
			b.WriteString("REDIS_PASSWORD=\n")
		}
		b.WriteString("\n")
	}

	// Upstream
	b.WriteString("# Upstream targets\n")
	if len(r.Routes) > 0 {
		b.WriteString(fmt.Sprintf("CSAR_UPSTREAM_URL=%s\n", r.Routes[0].TargetURL))
	} else {
		b.WriteString("CSAR_UPSTREAM_URL=http://localhost:3000\n")
	}
	b.WriteString("\n")

	// Token store
	if r.IncludePostgres {
		b.WriteString("# Token store DSN (for coordinator)\n")
		b.WriteString(fmt.Sprintf("CSAR_TOKEN_STORE_DSN=postgres://csar:%s@postgres:5432/csar?sslmode=disable\n", r.PostgresPassword))
		b.WriteString(fmt.Sprintf("POSTGRES_PASSWORD=%s\n", r.PostgresPassword))
		b.WriteString("\n")
	}

	// Metrics
	b.WriteString("# Metrics\n")
	b.WriteString("CSAR_METRICS_ADDR=:9100\n")

	return b.String()
}

// ─── Summary ────────────────────────────────────────────────────────────────────

func printGenerateSummary(r *GenerateResult) {
	fmt.Println()
	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(ColorSuccess).
		Padding(1, 2).
		Width(68)

	title := SuccessStyle.Render(fmt.Sprintf("%s Configuration generated!", IconRocket))

	lines := []string{
		title,
		"",
		LabelStyle.Render("Project:") + "  " + ValueStyle.Render(r.ProjectName),
		LabelStyle.Render("Profile:") + "  " + ValueStyle.Render(r.Profile),
		LabelStyle.Render("Listen:") + "  " + ValueStyle.Render(r.ListenAddr),
		LabelStyle.Render("TLS:") + "  " + boolToYesNo(r.EnableTLS),
		LabelStyle.Render("KMS:") + "  " + ValueStyle.Render(r.KMSProvider),
		LabelStyle.Render("Rate limits:") + "  " + ValueStyle.Render(r.RateLimitBackend),
		LabelStyle.Render("JWT auth:") + "  " + boolToYesNo(r.EnableJWT),
		LabelStyle.Render("Circuit breaker:") + "  " + boolToYesNo(r.EnableCircuitBreaker),
		LabelStyle.Render("Retry:") + "  " + boolToYesNo(r.EnableRetry),
		LabelStyle.Render("Coordinator:") + "  " + boolToYesNo(r.EnableCoordinator),
	}

	if len(r.Routes) > 0 {
		lines = append(lines, "")
		lines = append(lines, LabelStyle.Render("Routes:"))
		for _, rt := range r.Routes {
			lines = append(lines,
				fmt.Sprintf("  %s %s %s %s",
					MethodBadge(strings.ToUpper(rt.Method)),
					ValueStyle.Render(rt.Path),
					DimStyle.Render(IconArrow),
					DimStyle.Render(rt.TargetURL),
				),
			)
		}
	}

	if r.GenerateCompose {
		lines = append(lines,
			"",
			LabelStyle.Render("Docker Compose:") + "  " + SuccessStyle.Render("yes"),
		)
		var svc []string
		svc = append(svc, "router")
		if r.IncludeCoordinator {
			svc = append(svc, "coordinator")
		}
		if r.IncludeRedis {
			svc = append(svc, "redis")
		}
		if r.IncludePostgres {
			svc = append(svc, "postgres")
		}
		lines = append(lines,
			LabelStyle.Render("Services:") + "  " + ValueStyle.Render(strings.Join(svc, ", ")),
		)
	}

	lines = append(lines,
		"",
		LabelStyle.Render("Output:") + "  " + ValueStyle.Render(r.OutputDir),
		"",
		DimStyle.Render("Files created:"),
		DimStyle.Render("  "+IconCheck+" config.yaml"),
		DimStyle.Render("  "+IconCheck+" .env.example"),
	)
	if r.GenerateCompose {
		lines = append(lines, DimStyle.Render("  "+IconCheck+" docker-compose.yaml"))
	}

	lines = append(lines,
		"",
		DimStyle.Render("Next steps:"),
		DimStyle.Render("  1. cp .env.example .env  — fill in real values"),
		DimStyle.Render("  2. Edit config.yaml — add routes & backends"),
		DimStyle.Render("  3. csar-helper validate --config config.yaml"),
	)
	if r.GenerateCompose {
		lines = append(lines, DimStyle.Render("  4. docker compose up -d"))
	} else {
		lines = append(lines, DimStyle.Render("  4. csar --config config.yaml"))
	}

	fmt.Println(box.Render(strings.Join(lines, "\n")))
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
