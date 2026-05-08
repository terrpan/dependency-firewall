package service

import (
	"context"
	"time"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

func (s *AccessService) recordAudit(ctx context.Context, event domain.AuditEvent) error {
	if s.audit == nil {
		return nil
	}
	return s.audit.Record(ctx, event)
}

func (s *AccessService) metadataSummary(metadata *domain.ArtifactMetadata) map[string]any {
	if metadata == nil {
		return map[string]any{"available": false}
	}

	summary := map[string]any{
		"available":            true,
		"license_count":        len(metadata.Licenses),
		"vulnerability_count":  len(metadata.Vulnerabilities),
		"mutable_tag_detected": metadata.IsMutableTag,
	}
	if metadata.PublishedAt != nil {
		summary["published_at"] = metadata.PublishedAt.UTC().Format(time.RFC3339)
	}
	if metadata.MaxCVSS != nil {
		summary["max_cvss"] = *metadata.MaxCVSS
	}
	if s.audit != nil && s.audit.DetailLevel() == domain.AuditDetailLevelFull {
		summary["licenses"] = append([]string(nil), metadata.Licenses...)
		summary["vulnerabilities"] = append([]domain.Vulnerability(nil), metadata.Vulnerabilities...)
	}
	return summary
}
