package service

import (
	"context"
	"sync"
)

// DependencyGraphJobNotifier broadcasts wake-up signals to dependency graph
// workers when resolve jobs are enqueued. Signals carry no payload and are
// coalesced per subscriber, so a slow consumer receives at most one pending
// signal.
type DependencyGraphJobNotifier struct {
	mu          sync.Mutex
	subscribers map[chan struct{}]struct{}
}

// NewDependencyGraphJobNotifier creates a new DependencyGraphJobNotifier.
func NewDependencyGraphJobNotifier() *DependencyGraphJobNotifier {
	return &DependencyGraphJobNotifier{subscribers: make(map[chan struct{}]struct{})}
}

// Notify signals all subscribers that at least one job may be available.
func (n *DependencyGraphJobNotifier) Notify() {
	if n == nil {
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	for subscriber := range n.subscribers {
		select {
		case subscriber <- struct{}{}:
		default:
		}
	}
}

// WatchResolveJobs subscribes to job wake-up signals. The returned channel is
// closed when ctx is canceled.
func (n *DependencyGraphJobNotifier) WatchResolveJobs(ctx context.Context) <-chan struct{} {
	subscriber := make(chan struct{}, 1)
	n.mu.Lock()
	n.subscribers[subscriber] = struct{}{}
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
