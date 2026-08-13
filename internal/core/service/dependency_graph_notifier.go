package service

import (
	"context"
	"strings"
	"sync"
)

// DependencyGraphJobNotifier broadcasts wake-up signals to dependency graph
// workers when resolve jobs are enqueued. Signals are filtered by tenant and
// coalesced per subscriber, so a slow consumer receives at most one pending
// signal.
type DependencyGraphJobNotifier struct {
	mu          sync.Mutex
	subscribers map[chan struct{}]string
}

// NewDependencyGraphJobNotifier creates a new DependencyGraphJobNotifier.
func NewDependencyGraphJobNotifier() *DependencyGraphJobNotifier {
	return &DependencyGraphJobNotifier{subscribers: make(map[chan struct{}]string)}
}

// Notify signals matching subscribers that at least one tenant job may be available.
func (n *DependencyGraphJobNotifier) Notify(tenantID string) {
	if n == nil {
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	for subscriber, tenantScope := range n.subscribers {
		if tenantScope != "*" && tenantScope != tenantID {
			continue
		}
		select {
		case subscriber <- struct{}{}:
		default:
		}
	}
}

// WatchResolveJobs subscribes to job wake-up signals. The returned channel is
// closed when ctx is canceled.
func (n *DependencyGraphJobNotifier) WatchResolveJobs(ctx context.Context, tenantID string) <-chan struct{} {
	subscriber := make(chan struct{}, 1)
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		tenantID = "*"
	}
	n.mu.Lock()
	n.subscribers[subscriber] = tenantID
	n.mu.Unlock()

	go func() {
		<-ctx.Done()
		n.mu.Lock()
		delete(n.subscribers, subscriber)
		n.mu.Unlock()
		close(subscriber)
	}()
	return subscriber
}
