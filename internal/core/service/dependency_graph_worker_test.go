package service

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

type claimRecordingResolver struct {
	claims chan string
}

func (r *claimRecordingResolver) ClaimNextResolveJob(_ context.Context, tenantID string, _ time.Time) (*domain.DependencyGraphResolveRequest, error) {
	select {
	case r.claims <- tenantID:
	default:
	}
	return nil, nil
}

func (r *claimRecordingResolver) CompleteResolve(context.Context, domain.DependencyGraphResolveRequest, []domain.DependencyGraphNode, []domain.DependencyGraphEdge, string) error {
	return nil
}

func (r *claimRecordingResolver) FailResolve(context.Context, domain.DependencyGraphResolveRequest, string, time.Time) error {
	return nil
}

func TestDependencyGraphWorker_WakesOnJobNotification(t *testing.T) {
	t.Parallel()

	resolver := &claimRecordingResolver{claims: make(chan string, 1)}
	notifier := NewDependencyGraphJobNotifier()
	worker := NewDependencyGraphWorker(resolver, notifier, DependencyGraphWorkerConfig{
		Enabled:      true,
		TenantID:     "tenant-a",
		PollInterval: time.Hour,
	}, slog.New(slog.DiscardHandler))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = worker.Run(ctx)
	}()

	// Without a notification the worker must stay idle: the first poll tick
	// is an hour away.
	select {
	case <-resolver.claims:
		t.Fatal("worker claimed a job before any notification or poll tick")
	case <-time.After(50 * time.Millisecond):
	}

	// Wait for the worker subscription to be registered, then notify.
	deadline := time.After(2 * time.Second)
	for {
		notifier.Notify("tenant-a")
		select {
		case tenantID := <-resolver.claims:
			if tenantID != "tenant-a" {
				t.Fatalf("worker claimed tenant %q, want tenant-a", tenantID)
			}
		case <-time.After(20 * time.Millisecond):
			continue
		case <-deadline:
			t.Fatal("worker did not claim a job after notification")
		}
		break
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("worker did not stop after context cancellation")
	}
}

func TestDependencyGraphWorker_RunsWithoutWatcher(t *testing.T) {
	t.Parallel()

	resolver := &claimRecordingResolver{claims: make(chan string, 1)}
	worker := NewDependencyGraphWorker(resolver, nil, DependencyGraphWorkerConfig{
		Enabled:      true,
		PollInterval: 10 * time.Millisecond,
	}, slog.New(slog.DiscardHandler))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = worker.Run(ctx)
	}()

	select {
	case <-resolver.claims:
	case <-time.After(2 * time.Second):
		t.Fatal("worker did not poll for jobs")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("worker did not stop after context cancellation")
	}
}
