// oci_cache.go configures OCI-specific HTTP and artifact cache infrastructure.
package bootstrap

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/danielterry/dependency-firewall/internal/config"
	"github.com/danielterry/dependency-firewall/internal/core/port"
	"github.com/danielterry/dependency-firewall/internal/infra/ocicache"
)

func newOCIHTTPClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.ResponseHeaderTimeout = 30 * time.Second
	transport.IdleConnTimeout = 90 * time.Second
	transport.TLSHandshakeTimeout = 10 * time.Second
	transport.ExpectContinueTimeout = time.Second
	transport.DialContext = (&net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}).DialContext

	return &http.Client{Transport: transport}
}

func newOCIArtifactCache(cfg config.OCICacheConfig) (port.OCIArtifactCache, error) {
	switch strings.ToLower(strings.TrimSpace(cfg.Backend)) {
	case "", "disk":
		return ocicache.NewDiskCache(ocicache.DiskCacheOptions{
			RootDir:    cfg.RootDir,
			MaxBytes:   cfg.MaxBytes,
			MaxAge:     cfg.MaxAge,
			MaxEntries: cfg.MaxEntries,
		})
	case "s3", "gcs":
		return nil, fmt.Errorf("OCI cache backend %q is not implemented yet", cfg.Backend)
	default:
		return nil, fmt.Errorf("unsupported OCI cache backend %q", cfg.Backend)
	}
}
