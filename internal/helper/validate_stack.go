package helper

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// StackCheckResult contains the results of a stack validation pre-flight check.
type StackCheckResult struct {
	Checks   []StackCheck
	HasError bool
}

// StackCheck is a single validation check result.
type StackCheck struct {
	Level   string // "error", "warning", "info"
	Check   string // what was checked
	Message string // result message
}

// ValidateStack runs pre-flight checks on a deployment stack.
// It examines the compose file, .env, and config.yaml for common misconfigurations.
func ValidateStack(stackDir string) *StackCheckResult {
	result := &StackCheckResult{}

	// 1. Check if config.yaml exists
	configPath := filepath.Join(stackDir, "config.yaml")
	checkFileExists(result, configPath, "config.yaml", "error")

	// 2. Check if .env exists (warning only — .env.example is fine)
	envPath := filepath.Join(stackDir, ".env")
	envExamplePath := filepath.Join(stackDir, ".env.example")
	if _, err := os.Stat(envPath); os.IsNotExist(err) {
		if _, err := os.Stat(envExamplePath); err == nil {
			result.addWarning(".env file",
				".env file not found but .env.example exists. Copy it: cp .env.example .env")
		} else {
			result.addWarning(".env file",
				".env file not found. Environment variables may be missing.")
		}
	} else {
		result.addInfo(".env file", ".env file found")
		checkEnvVars(result, envPath)
	}

	// 3. Check docker-compose.yaml volume mounts
	composePath := filepath.Join(stackDir, "docker-compose.yaml")
	if _, err := os.Stat(composePath); err == nil {
		result.addInfo("docker-compose.yaml", "docker-compose.yaml found")
		checkComposeVolumeMounts(result, composePath, stackDir)
	}

	// 4. Check TLS cert paths if TLS directory is referenced
	tlsDir := filepath.Join(stackDir, "tls")
	if _, err := os.Stat(tlsDir); err == nil {
		result.addInfo("TLS directory", "tls/ directory found")
		checkTLSCerts(result, tlsDir)
	} else {
		// Check if config.yaml references TLS
		if configReferencesPath(configPath, "cert_file") || configReferencesPath(configPath, "key_file") {
			result.addWarning("TLS directory",
				"Config references TLS certificates but tls/ directory not found. "+
					"Run: csar-helper generate to create dev certs.")
		}
	}

	// 5. Check DB DSN syntax in .env
	if _, err := os.Stat(envPath); err == nil {
		checkDBDSN(result, envPath)
	}

	return result
}

func checkFileExists(result *StackCheckResult, path, name, level string) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		if level == "error" {
			result.addError(name, fmt.Sprintf("%s not found at %s", name, path))
		} else {
			result.addWarning(name, fmt.Sprintf("%s not found at %s", name, path))
		}
	} else {
		result.addInfo(name, fmt.Sprintf("%s found", name))
	}
}

func checkEnvVars(result *StackCheckResult, envPath string) {
	f, err := os.Open(envPath)
	if err != nil {
		return
	}
	defer f.Close()

	vars := make(map[string]string)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			vars[parts[0]] = parts[1]
		}
	}

	// Check for placeholder/empty critical vars
	criticalVars := []string{
		"CSAR_KMS_PROVIDER",
	}
	for _, v := range criticalVars {
		val, ok := vars[v]
		if !ok {
			result.addWarning("env: "+v, v+" is not set in .env")
		} else if val == "" || strings.Contains(val, "<your-") || strings.Contains(val, "placeholder") {
			result.addWarning("env: "+v, v+" appears to have a placeholder value")
		}
	}

	// Check Yandex IAM token if KMS is yandexapi
	if vars["CSAR_KMS_PROVIDER"] == "yandexapi" {
		if iam, ok := vars["YANDEX_IAM_TOKEN"]; !ok || iam == "" || strings.Contains(iam, "<your-") {
			result.addError("env: YANDEX_IAM_TOKEN",
				"YANDEX_IAM_TOKEN is required when CSAR_KMS_PROVIDER=yandexapi. "+
					"Generate with: yc iam create-token")
		}
	}

	// Check Postgres password
	if _, ok := vars["POSTGRES_PASSWORD"]; ok {
		if vars["POSTGRES_PASSWORD"] == "" {
			result.addWarning("env: POSTGRES_PASSWORD", "POSTGRES_PASSWORD is empty")
		}
	}
}

// checkComposeVolumeMounts parses docker-compose.yaml (basic regex) and checks
// that host paths in volume mounts exist.
func checkComposeVolumeMounts(result *StackCheckResult, composePath, stackDir string) {
	data, err := os.ReadFile(composePath)
	if err != nil {
		return
	}

	// Simple regex to find volume mounts like "./tls:/etc/csar/tls:ro"
	volumeRegex := regexp.MustCompile(`^\s*-\s*(\./[^:]+):`)
	lines := strings.Split(string(data), "\n")

	for _, line := range lines {
		matches := volumeRegex.FindStringSubmatch(line)
		if len(matches) >= 2 {
			hostPath := filepath.Join(stackDir, matches[1])
			if _, err := os.Stat(hostPath); os.IsNotExist(err) {
				result.addWarning("volume mount: "+matches[1],
					fmt.Sprintf("Volume mount host path %s does not exist", hostPath))
			}
		}
	}
}

func checkTLSCerts(result *StackCheckResult, tlsDir string) {
	requiredCerts := []string{"ca.pem", "server-cert.pem", "server-key.pem"}
	for _, cert := range requiredCerts {
		path := filepath.Join(tlsDir, cert)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			result.addWarning("TLS: "+cert,
				fmt.Sprintf("Expected TLS file %s not found", path))
		}
	}
}

func checkDBDSN(result *StackCheckResult, envPath string) {
	f, err := os.Open(envPath)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "CSAR_TOKEN_STORE_DSN=") {
			dsn := strings.TrimPrefix(line, "CSAR_TOKEN_STORE_DSN=")
			if dsn == "" {
				result.addWarning("DB DSN", "CSAR_TOKEN_STORE_DSN is empty")
				return
			}
			// Basic URL validation
			_, err := url.Parse(dsn)
			if err != nil {
				result.addError("DB DSN",
					fmt.Sprintf("CSAR_TOKEN_STORE_DSN has invalid URL syntax: %v", err))
			} else if !strings.HasPrefix(dsn, "postgres://") && !strings.HasPrefix(dsn, "postgresql://") &&
				!strings.HasPrefix(dsn, "mysql://") && !strings.HasPrefix(dsn, "sqlite://") {
				result.addWarning("DB DSN",
					"CSAR_TOKEN_STORE_DSN doesn't start with a known scheme (postgres://, mysql://, sqlite://)")
			} else {
				result.addInfo("DB DSN", "CSAR_TOKEN_STORE_DSN syntax looks valid")
			}
			return
		}
	}
}

func configReferencesPath(configPath, needle string) bool {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return false
	}
	return strings.Contains(string(data), needle)
}

func (r *StackCheckResult) addError(check, message string) {
	r.Checks = append(r.Checks, StackCheck{Level: "error", Check: check, Message: message})
	r.HasError = true
}

func (r *StackCheckResult) addWarning(check, message string) {
	r.Checks = append(r.Checks, StackCheck{Level: "warning", Check: check, Message: message})
}

func (r *StackCheckResult) addInfo(check, message string) {
	r.Checks = append(r.Checks, StackCheck{Level: "info", Check: check, Message: message})
}
