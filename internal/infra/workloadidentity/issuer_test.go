package workloadidentity

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

func TestLocalCAIssuer_IgnoresRequestedIdentityAndIssuesClientOnlyCertificate(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "workload-ca"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(2 * time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	caKeyDER, err := x509.MarshalPKCS8PrivateKey(caKey)
	require.NoError(t, err)
	caKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: caKeyDER})
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	serverKeyDER, err := x509.MarshalPKCS8PrivateKey(serverKey)
	require.NoError(t, err)

	directory := t.TempDir()
	caFile := writeTestPEM(t, directory, "ca.pem", caPEM)
	caKeyFile := writeTestPEM(t, directory, "ca-key.pem", caKeyPEM)
	serverKeyFile := writeTestPEM(
		t,
		directory,
		"server-key.pem",
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: serverKeyDER}),
	)
	issuer, err := NewLocalCAIssuer(LocalCAConfig{
		CACertificateFile: caFile, CAPrivateKeyFile: caKeyFile, ControlPlaneKeyFile: serverKeyFile,
		ServerTrustBundleFile: caFile, CertificateValidity: 30 * 24 * time.Hour,
	})
	require.NoError(t, err)

	proxyKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	requestedURI, err := url.Parse("spiffe://attacker/tenant/other")
	require.NoError(t, err)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "attacker",
		},
		DNSNames: []string{"attacker.example"},
		URIs:     []*url.URL{requestedURI},
	}, proxyKey)
	require.NoError(t, err)
	canonical := "spiffe://dependency-firewall/tenant/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/proxy/bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"

	issued, err := issuer.IssueWorkloadCertificate(
		context.Background(),
		domain.WorkloadCertificateRequest{CSRDER: csrDER, CanonicalIdentity: canonical},
	)
	require.NoError(t, err)
	block, _ := pem.Decode(issued.CertificateChainPEM)
	require.NotNil(t, block)
	certificate, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	assert.Empty(t, certificate.Subject.CommonName)
	assert.Empty(t, certificate.DNSNames)
	require.Len(t, certificate.URIs, 1)
	assert.Equal(t, canonical, certificate.URIs[0].String())
	assert.Equal(t, x509.KeyUsageDigitalSignature, certificate.KeyUsage)
	assert.Equal(t, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, certificate.ExtKeyUsage)
	assert.False(t, issued.NotAfter.After(caTemplate.NotAfter))
	assert.NotContains(t, string(issued.CertificateChainPEM), "PRIVATE KEY")
}

func TestLocalCAIssuer_RejectsControlPlaneServerKeyReuse(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(caKey)
	require.NoError(t, err)
	certFile := writeTestPEM(t, directory, "ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyFile := writeTestPEM(t, directory, "key.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))

	_, err = NewLocalCAIssuer(LocalCAConfig{
		CACertificateFile: certFile, CAPrivateKeyFile: keyFile, ControlPlaneKeyFile: keyFile,
		ServerTrustBundleFile: certFile, CertificateValidity: time.Hour,
	})
	require.ErrorContains(t, err, "must not be the control-plane server key")
}

func writeTestPEM(t *testing.T, directory, name string, contents []byte) string {
	t.Helper()
	path := filepath.Join(directory, name)
	require.NoError(t, os.WriteFile(path, contents, 0o600))
	return path
}
