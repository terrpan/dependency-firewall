package ocicache

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/core/port"
)

// DiskCacheOptions configures the disk-backed OCI artifact cache.
type DiskCacheOptions struct {
	RootDir    string
	MaxBytes   int64
	MaxAge     time.Duration
	MaxEntries int
}

// DiskCache implements port.OCIArtifactCache on the local filesystem.
type DiskCache struct {
	rootDir    string
	maxBytes   int64
	maxAge     time.Duration
	maxEntries int
}

type artifactMetadata struct {
	ContentType string            `json:"content_type"`
	Headers     map[string]string `json:"headers"`
}

type diskWriteSession struct {
	cache        *DiskCache
	tenantID     string
	upstreamID   string
	kind         port.OCIArtifactKind
	digest       string
	file         *os.File
	tempDataPath string
	finalData    string
	finalMeta    string
	descriptor   port.OCIArtifactDescriptor
	aborted      bool
	committed    bool
}

type cachedFile struct {
	dataPath string
	metaPath string
	size     int64
	modTime  time.Time
}

// NewDiskCache creates a disk-backed OCI artifact cache.
func NewDiskCache(opts DiskCacheOptions) (*DiskCache, error) {
	root := strings.TrimSpace(opts.RootDir)
	if root == "" {
		return nil, fmt.Errorf("disk cache root directory is required")
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return nil, fmt.Errorf("creating cache root: %w", err)
	}

	return &DiskCache{
		rootDir:    root,
		maxBytes:   opts.MaxBytes,
		maxAge:     opts.MaxAge,
		maxEntries: opts.MaxEntries,
	}, nil
}

// Get retrieves a cached OCI artifact. Returns domain.ErrCacheMiss if not found.
func (c *DiskCache) Get(
	_ context.Context,
	tenantID string,
	upstreamID string,
	kind port.OCIArtifactKind,
	digest string,
) (*port.UpstreamResponse, error) {
	dataPath, metaPath, err := c.finalPaths(tenantID, upstreamID, kind, digest)
	if err != nil {
		return nil, err
	}

	metaBytes, err := os.ReadFile(metaPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, domain.ErrCacheMiss
		}
		return nil, fmt.Errorf("reading cache metadata: %w", err)
	}

	var meta artifactMetadata
	if err := json.Unmarshal(metaBytes, &meta); err != nil {
		return nil, fmt.Errorf("decoding cache metadata: %w", err)
	}

	file, err := os.Open(dataPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, domain.ErrCacheMiss
		}
		return nil, fmt.Errorf("opening cached artifact: %w", err)
	}

	return &port.UpstreamResponse{
		StatusCode:  200,
		ContentType: meta.ContentType,
		Headers:     cloneHeaders(meta.Headers),
		Body:        file,
	}, nil
}

// StartWrite begins a staged OCI artifact cache write.
func (c *DiskCache) StartWrite(
	_ context.Context,
	tenantID string,
	upstreamID string,
	kind port.OCIArtifactKind,
	digest string,
	descriptor port.OCIArtifactDescriptor,
) (port.OCIArtifactWriter, error) {
	finalData, finalMeta, err := c.finalPaths(tenantID, upstreamID, kind, digest)
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(filepath.Dir(finalData), 0o755); err != nil {
		return nil, fmt.Errorf("creating cache directory: %w", err)
	}

	scopeRoot, err := c.scopeRoot(tenantID, upstreamID)
	if err != nil {
		return nil, err
	}
	tempDir := filepath.Join(scopeRoot, ".tmp")
	if err := os.MkdirAll(tempDir, 0o755); err != nil {
		return nil, fmt.Errorf("creating cache temp directory: %w", err)
	}

	file, err := os.CreateTemp(tempDir, string(kind)+"-*.part")
	if err != nil {
		return nil, fmt.Errorf("creating cache temp file: %w", err)
	}

	return &diskWriteSession{
		cache:        c,
		tenantID:     tenantID,
		upstreamID:   upstreamID,
		kind:         kind,
		digest:       digest,
		file:         file,
		tempDataPath: file.Name(),
		finalData:    finalData,
		finalMeta:    finalMeta,
		descriptor: port.OCIArtifactDescriptor{
			ContentType: descriptor.ContentType,
			Headers:     cloneHeaders(descriptor.Headers),
		},
	}, nil
}

func (s *diskWriteSession) Write(p []byte) (int, error) {
	if s.aborted || s.committed {
		return 0, fmt.Errorf("cache write session already closed")
	}
	return s.file.Write(p)
}

func (s *diskWriteSession) Commit(ctx context.Context) error {
	if s.aborted || s.committed {
		return nil
	}

	if err := s.file.Close(); err != nil {
		_ = os.Remove(s.tempDataPath)
		return fmt.Errorf("closing cache temp file: %w", err)
	}

	metaBytes, err := json.Marshal(artifactMetadata{
		ContentType: s.descriptor.ContentType,
		Headers:     cloneHeaders(s.descriptor.Headers),
	})
	if err != nil {
		_ = os.Remove(s.tempDataPath)
		return fmt.Errorf("encoding cache metadata: %w", err)
	}

	tempMeta := s.tempDataPath + ".meta"
	if err := os.WriteFile(tempMeta, metaBytes, 0o644); err != nil {
		_ = os.Remove(s.tempDataPath)
		return fmt.Errorf("writing cache metadata: %w", err)
	}

	if _, err := os.Stat(s.finalData); err == nil {
		_ = os.Remove(s.tempDataPath)
		_ = os.Remove(tempMeta)
		s.committed = true
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		_ = os.Remove(s.tempDataPath)
		_ = os.Remove(tempMeta)
		return fmt.Errorf("checking cache destination: %w", err)
	}

	if err := os.Rename(s.tempDataPath, s.finalData); err != nil {
		_ = os.Remove(s.tempDataPath)
		_ = os.Remove(tempMeta)
		return fmt.Errorf("promoting cached artifact: %w", err)
	}
	if err := os.Rename(tempMeta, s.finalMeta); err != nil {
		_ = os.Remove(s.finalData)
		_ = os.Remove(tempMeta)
		return fmt.Errorf("promoting cache metadata: %w", err)
	}

	s.committed = true
	if err := s.cache.enforceLimits(ctx, s.tenantID, s.upstreamID); err != nil {
		return fmt.Errorf("enforcing cache limits: %w", err)
	}
	return nil
}

func (s *diskWriteSession) Abort() error {
	if s.aborted || s.committed {
		return nil
	}
	s.aborted = true
	if s.file != nil {
		_ = s.file.Close()
	}
	if err := os.Remove(s.tempDataPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("removing cache temp file: %w", err)
	}
	return nil
}

func (c *DiskCache) enforceLimits(_ context.Context, tenantID, upstreamID string) error {
	if c.maxAge <= 0 && c.maxEntries <= 0 && c.maxBytes <= 0 {
		return nil
	}

	scopeRoot, err := c.scopeRoot(tenantID, upstreamID)
	if err != nil {
		return err
	}
	files, err := c.collectScopedFiles(scopeRoot)
	if err != nil {
		return err
	}

	now := time.Now()
	if c.maxAge > 0 {
		var kept []cachedFile
		for _, file := range files {
			if now.Sub(file.modTime) > c.maxAge {
				if err := removeCachedFile(file); err != nil {
					return err
				}
				continue
			}
			kept = append(kept, file)
		}
		files = kept
	}

	if c.maxEntries <= 0 && c.maxBytes <= 0 {
		return nil
	}

	sort.Slice(files, func(i, j int) bool {
		return files[i].modTime.Before(files[j].modTime)
	})

	var totalBytes int64
	for _, file := range files {
		totalBytes += file.size
	}

	for len(files) > 0 && ((c.maxEntries > 0 && len(files) > c.maxEntries) || (c.maxBytes > 0 && totalBytes > c.maxBytes)) {
		oldest := files[0]
		files = files[1:]
		totalBytes -= oldest.size
		if err := removeCachedFile(oldest); err != nil {
			return err
		}
	}

	return nil
}

func (c *DiskCache) collectScopedFiles(scopeRoot string) ([]cachedFile, error) {
	if _, err := os.Stat(scopeRoot); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("stat OCI cache scope root: %w", err)
	}

	var files []cachedFile
	err := filepath.WalkDir(scopeRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".tmp" {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".data" {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		files = append(files, cachedFile{
			dataPath: path,
			metaPath: strings.TrimSuffix(path, ".data") + ".meta.json",
			size:     info.Size(),
			modTime:  info.ModTime(),
		})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walking OCI cache scope: %w", err)
	}
	return files, nil
}

func removeCachedFile(file cachedFile) error {
	if err := os.Remove(file.dataPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("removing cached artifact: %w", err)
	}
	if err := os.Remove(file.metaPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("removing cached metadata: %w", err)
	}
	return nil
}

func (c *DiskCache) finalPaths(
	tenantID, upstreamID string,
	kind port.OCIArtifactKind,
	digest string,
) (string, string, error) {
	algo, encoded, err := splitDigest(digest)
	if err != nil {
		return "", "", err
	}
	scopeRoot, err := c.scopeRoot(tenantID, upstreamID)
	if err != nil {
		return "", "", err
	}
	base := filepath.Join(scopeRoot, string(kind), algo, encoded)
	return base + ".data", base + ".meta.json", nil
}

func (c *DiskCache) scopeRoot(tenantID, upstreamID string) (string, error) {
	tenantComponent, err := pathComponent("tenant_id", tenantID)
	if err != nil {
		return "", err
	}
	upstreamComponent, err := pathComponent("upstream_id", upstreamID)
	if err != nil {
		return "", err
	}
	return filepath.Join(c.rootDir, tenantComponent, upstreamComponent), nil
}

func splitDigest(digest string) (string, string, error) {
	algo, encoded, ok := strings.Cut(strings.TrimSpace(digest), ":")
	if !ok || algo == "" || encoded == "" {
		return "", "", fmt.Errorf("invalid OCI digest %q", digest)
	}
	return algo, encoded, nil
}

func pathComponent(name, value string) (string, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "", fmt.Errorf("OCI cache %s is required", name)
	}
	return url.PathEscape(trimmed), nil
}

func cloneHeaders(headers map[string]string) map[string]string {
	if len(headers) == 0 {
		return nil
	}
	cloned := make(map[string]string, len(headers))
	for k, v := range headers {
		cloned[k] = v
	}
	return cloned
}
