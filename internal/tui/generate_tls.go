package tui

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/charmbracelet/huh"
)

// TLSWizardAnswers holds the user's TLS certificate decisions.
type TLSWizardAnswers struct {
	HasExistingCerts bool
	GenerateCerts    bool
	CertDir          string // relative to output dir
	// Filled after generation
	CACertPath          string
	ServerCertPath      string
	ServerKeyPath       string
	CoordinatorCertPath string
	CoordinatorKeyPath  string
	ClientCertPath      string
	ClientKeyPath       string
}

// runTLSWizard asks the user about TLS certificates and optionally generates dev certs.
// Returns nil if TLS is not enabled.
func runTLSWizard(enableTLS bool, outputDir string) (*TLSWizardAnswers, error) {
	if !enableTLS {
		return nil, nil
	}

	ans := &TLSWizardAnswers{
		CertDir: "tls",
	}

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewNote().
				Title("  TLS Certificates").
				Description("TLS is enabled — you need certificates for the gateway.\n"+
					"The helper can generate self-signed dev certificates for you."),

			huh.NewConfirm().
				Title("Do you have existing certificates?").
				Description("If yes, you'll provide the paths. If no, we can generate dev certs.").
				Value(&ans.HasExistingCerts),
		),

		// Offer to generate certs — shown only when user doesn't have certs
		huh.NewGroup(
			huh.NewConfirm().
				Title("Generate self-signed dev certificates?").
				Description("Creates CA, server, coordinator and client certs in ./tls/").
				Value(&ans.GenerateCerts),
		).WithHideFunc(func() bool { return ans.HasExistingCerts }),
	).WithTheme(huh.ThemeCatppuccin())

	if err := form.Run(); err != nil {
		return nil, err
	}

	if ans.GenerateCerts && !ans.HasExistingCerts {
		certDir := filepath.Join(outputDir, ans.CertDir)
		if err := generateDevCerts(certDir, ans); err != nil {
			return nil, fmt.Errorf("generating dev certificates: %w", err)
		}
		fmt.Printf("  %s TLS certificates generated in %s/\n", IconCheck, certDir)
	}

	return ans, nil
}

// generateDevCerts creates a self-signed CA and issues server, coordinator,
// and client certificates — suitable for local development.
func generateDevCerts(certDir string, ans *TLSWizardAnswers) error {
	// 0700: only the owner can read/list the cert directory (contains private keys).
	if err := os.MkdirAll(certDir, 0o700); err != nil {
		return fmt.Errorf("creating cert directory: %w", err)
	}

	// ─── CA ──────────────────────────────────────────────────────────────────
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generating CA key: %w", err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"CSAR Dev CA"}, CommonName: "csar-dev-ca"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("creating CA certificate: %w", err)
	}

	caCertPath := filepath.Join(certDir, "ca.pem")
	if err := writePEM(caCertPath, "CERTIFICATE", caCertDER); err != nil {
		return err
	}
	ans.CACertPath = caCertPath

	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return fmt.Errorf("parsing CA certificate: %w", err)
	}

	// ─── Server cert ────────────────────────────────────────────────────────
	serverCertPath, serverKeyPath, err := issueCert(certDir, "server", caCert, caKey, false)
	if err != nil {
		return err
	}
	ans.ServerCertPath = serverCertPath
	ans.ServerKeyPath = serverKeyPath

	// ─── Coordinator cert ───────────────────────────────────────────────────
	coordCertPath, coordKeyPath, err := issueCert(certDir, "coordinator", caCert, caKey, true)
	if err != nil {
		return err
	}
	ans.CoordinatorCertPath = coordCertPath
	ans.CoordinatorKeyPath = coordKeyPath

	// ─── Client cert (for router → coordinator mTLS) ────────────────────────
	clientCertPath, clientKeyPath, err := issueCert(certDir, "client", caCert, caKey, false)
	if err != nil {
		return err
	}
	ans.ClientCertPath = clientCertPath
	ans.ClientKeyPath = clientKeyPath

	return nil
}

// issueCert creates a key pair and certificate signed by the given CA.
func issueCert(certDir, name string, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, isServer bool) (string, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("generating %s key: %w", name, err)
	}

	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{Organization: []string{"CSAR Dev"}, CommonName: "csar-" + name},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		DNSNames:     []string{"localhost", name, "csar-" + name},
	}

	if isServer {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	} else {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		return "", "", fmt.Errorf("creating %s certificate: %w", name, err)
	}

	certPath := filepath.Join(certDir, name+"-cert.pem")
	if err := writePEM(certPath, "CERTIFICATE", certDER); err != nil {
		return "", "", err
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", "", fmt.Errorf("marshalling %s key: %w", name, err)
	}

	keyPath := filepath.Join(certDir, name+"-key.pem")
	if err := writePEM(keyPath, "EC PRIVATE KEY", keyDER); err != nil {
		return "", "", err
	}

	return certPath, keyPath, nil
}

// writePEM writes a PEM block to disk.
// Private key files ("*PRIVATE*" block types) are created with 0600 permissions
// to prevent other users from reading the key material.
// Certificate files get 0644 (readable by all, writable by owner only).
func writePEM(path, blockType string, data []byte) error {
	perm := os.FileMode(0o644) // certificates: world-readable
	if strings.Contains(blockType, "PRIVATE") {
		perm = 0o600 // private keys: owner-only
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return fmt.Errorf("creating %s: %w", path, err)
	}
	defer f.Close()

	return pem.Encode(f, &pem.Block{Type: blockType, Bytes: data})
}
