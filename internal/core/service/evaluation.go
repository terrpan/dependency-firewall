package service

import (
	"context"
	"fmt"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/core/port"
)

// EvaluationService owns read-only evaluation queries for the control plane.
type EvaluationService struct {
	repo port.DecisionRepository
}

// NewEvaluationService creates a new EvaluationService.
func NewEvaluationService(repo port.DecisionRepository) *EvaluationService {
	return &EvaluationService{repo: repo}
}

// ListByTenant returns evaluations for a tenant.
func (s *EvaluationService) ListByTenant(
	ctx context.Context,
	tenantID string,
	limit, offset int,
	search string,
) ([]domain.Decision, error) {
	decisions, err := s.repo.ListByTenant(ctx, tenantID, limit, offset, search)
	if err != nil {
		return nil, fmt.Errorf("listing evaluations: %w", err)
	}
	return decisions, nil
}
