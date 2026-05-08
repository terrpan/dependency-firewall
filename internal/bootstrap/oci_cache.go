package bootstrap

import (
	"fmt"
	"strings"

	"github.com/danielterry/dependency-firewall/internal/config"
	"github.com/danielterry/dependency-firewall/internal/core/port"
	"github.com/danielterry/dependency-firewall/internal/infra/ocicache"
)

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
