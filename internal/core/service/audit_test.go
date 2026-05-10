package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

type stubAuditRecorder struct {
	err    error
	events []domain.AuditEvent
	calls  int
}

func (s *stubAuditRecorder) Record(_ context.Context, event *domain.AuditEvent) error {
	s.calls++
	if s.err != nil {
		return s.err
	}
	s.events = append(s.events, *event)
	return nil
}

func TestAuditService_RecordFailureModes(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	t.Run("fail closed returns audit unavailable", func(t *testing.T) {
		service := NewAuditService(
			&stubAuditRecorder{err: errors.New("postgres down")},
			nil,
			logger,
			true,
			domain.AuditFailureModeFailClosed,
			domain.AuditDetailLevelSummary,
		)

		err := service.Record(context.Background(), domain.AuditEvent{
			TenantID:  "tenant-1",
			EventType: domain.AuditEventEvaluationStarted,
		})

		require.ErrorIs(t, err, domain.ErrAuditUnavailable)
	})

	t.Run("fail open suppresses sink failure", func(t *testing.T) {
		service := NewAuditService(
			&stubAuditRecorder{err: errors.New("stdout blocked")},
			nil,
			logger,
			true,
			domain.AuditFailureModeFailOpen,
			domain.AuditDetailLevelSummary,
		)

		err := service.Record(context.Background(), domain.AuditEvent{
			TenantID:  "tenant-1",
			EventType: domain.AuditEventEvaluationStarted,
		})

		require.NoError(t, err)
	})

	t.Run("disabled service is a no-op", func(t *testing.T) {
		recorder := &stubAuditRecorder{}
		service := NewAuditService(
			recorder,
			nil,
			logger,
			false,
			domain.AuditFailureModeFailClosed,
			domain.AuditDetailLevelSummary,
		)

		err := service.Record(context.Background(), domain.AuditEvent{
			TenantID:  "tenant-1",
			EventType: domain.AuditEventEvaluationStarted,
		})

		require.NoError(t, err)
		assert.Empty(t, recorder.events)
	})

	t.Run("canceled context is ignored even when fail closed", func(t *testing.T) {
		recorder := &stubAuditRecorder{err: context.Canceled}
		service := NewAuditService(
			recorder,
			nil,
			logger,
			true,
			domain.AuditFailureModeFailClosed,
			domain.AuditDetailLevelSummary,
		)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		err := service.Record(ctx, domain.AuditEvent{
			TenantID:  "tenant-1",
			EventType: domain.AuditEventEvaluationStarted,
		})

		require.NoError(t, err)
		assert.Zero(t, recorder.calls)
	})
}
