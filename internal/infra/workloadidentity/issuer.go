// Package workloadidentity implements local workload certificate issuance.
package workloadidentity

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"time"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

// LocalCAConfig configures a private issuer without putting key material in application config values.
type LocalCAConfig struct {
	CACertificateFile     string
	CAPrivateKeyFile      string
	ControlPlaneKeyFile   string
	ServerTrustBundleFile string
	CertificateValidity   time.Duration
}

// LocalCAIssuer issues URI-only client certificates from an operator-managed private CA.
type LocalCAIssuer struct {
	certificate    *x509.Certificate
	privateKey     crypto.Signer
	caPEM          []byte
	serverTrustPEM []byte
	validity       time.Duration
	now            func() time.Time
}

// NewLocalCAIssuer loads and validates a local private CA.
//
//nolint:gocyclo // startup validation deliberately keeps every CA/key separation check fail-closed.
func NewLocalCAIssuer(cfg LocalCAConfig) (*LocalCAIssuer, error) {
	if cfg.CertificateValidity <= 0 {
		return nil, fmt.Errorf("workload certificate validity must be positive")
	}
	caPEM, err := readBoundedFile(cfg.CACertificateFile, 1<<20)
	if err != nil {
		return nil, fmt.Errorf("reading workload CA certificate: %w", err)
	}
	caBlock, rest := pem.Decode(caPEM)
	if caBlock == nil || caBlock.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("parsing workload CA certificate: exactly one certificate is required")
	}
	certificate, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing workload CA certificate: %w", err)
	}
	if !certificate.IsCA || !certificate.BasicConstraintsValid || certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, fmt.Errorf("workload issuer certificate is not a valid signing CA")
	}
	if now := time.Now(); now.Before(certificate.NotBefore) || now.After(certificate.NotAfter) {
		return nil, fmt.Errorf("workload issuer certificate is not currently valid")
	}
	keyPEM, err := readBoundedFile(cfg.CAPrivateKeyFile, 1<<20)
	if err != nil {
		return nil, fmt.Errorf("reading workload CA private key: %w", err)
	}
	privateKey, err := parseSigner(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parsing workload CA private key: %w", err)
	}
	if !publicKeysEqual(certificate.PublicKey, privateKey.Public()) {
		return nil, fmt.Errorf("workload CA certificate and private key do not match")
	}
	if cfg.ControlPlaneKeyFile != "" {
		serverKeyPEM, err := readBoundedFile(cfg.ControlPlaneKeyFile, 1<<20)
		if err != nil {
			return nil, fmt.Errorf("reading control-plane private key for separation check: %w", err)
		}
		serverKey, err := parseSigner(serverKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("parsing control-plane private key for separation check: %w", err)
		}
		if publicKeysEqual(privateKey.Public(), serverKey.Public()) {
			return nil, fmt.Errorf("workload CA private key must not be the control-plane server key")
		}
	}
	serverTrustPEM, err := readBoundedFile(cfg.ServerTrustBundleFile, 1<<20)
	if err != nil {
		return nil, fmt.Errorf("reading gRPC server trust bundle: %w", err)
	}
	return &LocalCAIssuer{
		certificate:    certificate,
		privateKey:     privateKey,
		caPEM:          append([]byte(nil), caPEM...),
		serverTrustPEM: serverTrustPEM,
		validity:       cfg.CertificateValidity,
		now:            time.Now,
	}, nil
}

// IssueWorkloadCertificate issues a random-serial, URI-only client certificate.
func (i *LocalCAIssuer) IssueWorkloadCertificate(
	_ context.Context,
	request domain.WorkloadCertificateRequest,
) (*domain.IssuedWorkloadCertificate, error) {
	csr, err := x509.ParseCertificateRequest(request.CSRDER)
	if err != nil || csr.CheckSignature() != nil {
		return nil, fmt.Errorf("invalid verified proxy CSR")
	}
	publicKey, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || publicKey.Curve != elliptic.P256() {
		return nil, fmt.Errorf("proxy CSR must use ECDSA P-256")
	}
	identity, err := url.Parse(request.CanonicalIdentity)
	if err != nil || identity.Scheme != "spiffe" || identity.Host != "dependency-firewall" || identity.RawQuery != "" ||
		identity.Fragment != "" {
		return nil, fmt.Errorf("invalid canonical workload identity")
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, fmt.Errorf("generating workload certificate serial: %w", err)
	}
	now := i.now().UTC()
	notAfter := now.Add(i.validity)
	if notAfter.After(i.certificate.NotAfter) {
		notAfter = i.certificate.NotAfter
	}
	if !notAfter.After(now) {
		return nil, fmt.Errorf("workload issuer expires before the requested certificate can be issued")
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:                  []*url.URL{identity},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, i.certificate, publicKey, i.privateKey)
	if err != nil {
		return nil, fmt.Errorf("creating workload certificate: %w", err)
	}
	chain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	chain = append(chain, i.caPEM...)
	return &domain.IssuedWorkloadCertificate{
		CertificateChainPEM:  chain,
		ServerTrustBundlePEM: append([]byte(nil), i.serverTrustPEM...),
		Serial:               serial.Text(16),
		NotAfter:             notAfter,
	}, nil
}

func readBoundedFile(path string, limit int64) ([]byte, error) {
	//nolint:gosec // all paths are operator-supplied static configuration, never request input.
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() <= 0 || info.Size() > limit {
		return nil, fmt.Errorf("file size must be between 1 and %d bytes", limit)
	}
	return os.ReadFile(path) //nolint:gosec // validated static path and bounded size.
}

func parseSigner(keyPEM []byte) (crypto.Signer, error) {
	block, rest := pem.Decode(keyPEM)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("exactly one PEM private key is required")
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if signer, ok := key.(crypto.Signer); ok {
			return signer, nil
		}
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("unsupported private key encoding")
}

func publicKeysEqual(left, right any) bool {
	leftDER, leftErr := x509.MarshalPKIXPublicKey(left)
	rightDER, rightErr := x509.MarshalPKIXPublicKey(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftDER, rightDER)
}

var _ crypto.Signer = (*rsa.PrivateKey)(nil)
