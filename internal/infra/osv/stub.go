// Package osv provides enrichment clients for vulnerability data.
package osv

import (
	"context"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

// StubEnricher is a no-op enricher used until the real OSV client is implemented.
type StubEnricher struct{}

// NewStubEnricher creates a new StubEnricher.
func NewStubEnricher() *StubEnricher {
	return &StubEnricher{}
}

// Enrich returns nil metadata as a no-op placeholder.
func (s *StubEnricher) Enrich(_ context.Context, _ domain.ArtifactIdentity) (*domain.ArtifactMetadata, error) {
	return nil, nil
}
