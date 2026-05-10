package controlplanegrpc

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/danielterry/dependency-firewall/internal/config"
)

func TestDialAndServerOptionsDefaultToInsecure(t *testing.T) {
	t.Parallel()

	dialOptions, err := DialOptions()
	require.NoError(t, err)
	require.NotEmpty(t, dialOptions)

	serverOptions, err := ServerOptions()
	require.NoError(t, err)
	require.NotEmpty(t, serverOptions)
}

func TestMTLSOptionsRequireReadableCertificateFiles(t *testing.T) {
	t.Parallel()

	cfg := config.BundleTLSConfig{
		Mode:     "mtls",
		CAFile:   "missing-ca.pem",
		CertFile: "missing-cert.pem",
		KeyFile:  "missing-key.pem",
	}

	_, err := DialOptions(cfg)
	require.Error(t, err)

	_, err = ServerOptions(cfg)
	require.Error(t, err)
}
