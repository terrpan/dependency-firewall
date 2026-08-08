package ingest

import (
	"context"
	"fmt"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

// DependencyGraphQueue adapts the proxy ingestion gRPC client to the dependency graph queue port.
type DependencyGraphQueue struct {
	client *GRPCClient
}

// NewDependencyGraphQueue creates a gRPC-backed dependency graph queue.
func NewDependencyGraphQueue(client *GRPCClient) *DependencyGraphQueue {
	return &DependencyGraphQueue{client: client}
}

// EnqueueResolve sends one async graph-resolution request to the control plane.
func (q *DependencyGraphQueue) EnqueueResolve(ctx context.Context, req domain.DependencyGraphResolveRequest) (bool, error) {
	if q == nil || q.client == nil {
		return false, fmt.Errorf("enqueueing dependency graph resolve: client unavailable")
	}
	return q.client.EnqueueDependencyGraphResolve(ctx, req)
}

// LocalDependencyGraphQueue adapts an in-process ProxyIngestService to the dependency graph queue port.
type LocalDependencyGraphQueue struct {
	service interface {
		EnqueueDependencyGraphResolve(context.Context, domain.DependencyGraphResolveRequest) (bool, error)
	}
}

// NewLocalDependencyGraphQueue creates an in-process dependency graph queue.
func NewLocalDependencyGraphQueue(service interface {
	EnqueueDependencyGraphResolve(context.Context, domain.DependencyGraphResolveRequest) (bool, error)
}) *LocalDependencyGraphQueue {
	return &LocalDependencyGraphQueue{service: service}
}

// EnqueueResolve sends one async graph-resolution request in-process.
func (q *LocalDependencyGraphQueue) EnqueueResolve(ctx context.Context, req domain.DependencyGraphResolveRequest) (bool, error) {
	if q == nil || q.service == nil {
		return false, fmt.Errorf("enqueueing dependency graph resolve: service unavailable")
	}
	return q.service.EnqueueDependencyGraphResolve(ctx, req)
}
