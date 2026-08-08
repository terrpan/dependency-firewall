package service

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDependencyGraphJobNotifier_DeliversSignalToSubscribers(t *testing.T) {
	t.Parallel()

	notifier := NewDependencyGraphJobNotifier()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	first := notifier.WatchResolveJobs(ctx)
	second := notifier.WatchResolveJobs(ctx)

	notifier.Notify()

	select {
	case <-first:
	case <-time.After(time.Second):
		t.Fatal("first subscriber did not receive notification")
	}
	select {
	case <-second:
	case <-time.After(time.Second):
		t.Fatal("second subscriber did not receive notification")
	}
}

func TestDependencyGraphJobNotifier_CoalescesPendingSignals(t *testing.T) {
	t.Parallel()

	notifier := NewDependencyGraphJobNotifier()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	subscriber := notifier.WatchResolveJobs(ctx)
	notifier.Notify()
	notifier.Notify()
	notifier.Notify()

	select {
	case <-subscriber:
	case <-time.After(time.Second):
		t.Fatal("subscriber did not receive notification")
	}
	select {
	case <-subscriber:
		t.Fatal("expected pending notifications to be coalesced into one signal")
	default:
	}
}

func TestDependencyGraphJobNotifier_ClosesChannelOnContextCancel(t *testing.T) {
	t.Parallel()

	notifier := NewDependencyGraphJobNotifier()
	ctx, cancel := context.WithCancel(context.Background())

	subscriber := notifier.WatchResolveJobs(ctx)
	cancel()

	select {
	case _, ok := <-subscriber:
		assert.False(t, ok, "expected channel to be closed")
	case <-time.After(time.Second):
		t.Fatal("channel was not closed after context cancellation")
	}

	require.NotPanics(t, notifier.Notify)
}

func TestDependencyGraphJobNotifier_NilNotifyIsSafe(t *testing.T) {
	t.Parallel()

	var notifier *DependencyGraphJobNotifier
	require.NotPanics(t, notifier.Notify)
}
