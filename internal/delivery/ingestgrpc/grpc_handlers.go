package ingestgrpc

import (
	"context"

	"google.golang.org/grpc"
)

func (s *Server) recordDecisionHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	req := &RecordDecisionRequest{}
	if err := dec(req); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(proxyIngestGRPCService).RecordDecision(ctx, req)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/" + serviceName + "/RecordDecision"}
	handler := func(ctx context.Context, req any) (any, error) {
		return srv.(proxyIngestGRPCService).RecordDecision(ctx, req.(*RecordDecisionRequest))
	}
	return interceptor(ctx, req, info, handler)
}

func (s *Server) getDecisionByArtifactHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	req := &GetDecisionByArtifactRequest{}
	if err := dec(req); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(proxyIngestGRPCService).GetDecisionByArtifact(ctx, req)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/" + serviceName + "/GetDecisionByArtifact"}
	handler := func(ctx context.Context, req any) (any, error) {
		return srv.(proxyIngestGRPCService).GetDecisionByArtifact(ctx, req.(*GetDecisionByArtifactRequest))
	}
	return interceptor(ctx, req, info, handler)
}

func (s *Server) listDecisionsByTenantHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	req := &ListDecisionsByTenantRequest{}
	if err := dec(req); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(proxyIngestGRPCService).ListDecisionsByTenant(ctx, req)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/" + serviceName + "/ListDecisionsByTenant"}
	handler := func(ctx context.Context, req any) (any, error) {
		return srv.(proxyIngestGRPCService).ListDecisionsByTenant(ctx, req.(*ListDecisionsByTenantRequest))
	}
	return interceptor(ctx, req, info, handler)
}

func (s *Server) hasRecentAllowHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	req := &HasRecentAllowRequest{}
	if err := dec(req); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(proxyIngestGRPCService).HasRecentAllow(ctx, req)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/" + serviceName + "/HasRecentAllow"}
	handler := func(ctx context.Context, req any) (any, error) {
		return srv.(proxyIngestGRPCService).HasRecentAllow(ctx, req.(*HasRecentAllowRequest))
	}
	return interceptor(ctx, req, info, handler)
}

func (s *Server) recordAuditEventHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	req := &RecordAuditEventRequest{}
	if err := dec(req); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(proxyIngestGRPCService).RecordAuditEvent(ctx, req)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/" + serviceName + "/RecordAuditEvent"}
	handler := func(ctx context.Context, req any) (any, error) {
		return srv.(proxyIngestGRPCService).RecordAuditEvent(ctx, req.(*RecordAuditEventRequest))
	}
	return interceptor(ctx, req, info, handler)
}

func (s *Server) enqueueDependencyGraphResolveHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	req := &EnqueueDependencyGraphResolveRequest{}
	if err := dec(req); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(proxyIngestGRPCService).EnqueueDependencyGraphResolve(ctx, req)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/" + serviceName + "/EnqueueDependencyGraphResolve"}
	handler := func(ctx context.Context, req any) (any, error) {
		return srv.(proxyIngestGRPCService).EnqueueDependencyGraphResolve(ctx, req.(*EnqueueDependencyGraphResolveRequest))
	}
	return interceptor(ctx, req, info, handler)
}

func (s *Server) claimDependencyGraphResolveHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	req := &ClaimDependencyGraphResolveRequest{}
	if err := dec(req); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(proxyIngestGRPCService).ClaimDependencyGraphResolve(ctx, req)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/" + serviceName + "/ClaimDependencyGraphResolve"}
	handler := func(ctx context.Context, req any) (any, error) {
		return srv.(proxyIngestGRPCService).ClaimDependencyGraphResolve(ctx, req.(*ClaimDependencyGraphResolveRequest))
	}
	return interceptor(ctx, req, info, handler)
}

func (s *Server) completeDependencyGraphResolveHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	req := &CompleteDependencyGraphResolveRequest{}
	if err := dec(req); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(proxyIngestGRPCService).CompleteDependencyGraphResolve(ctx, req)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/" + serviceName + "/CompleteDependencyGraphResolve"}
	handler := func(ctx context.Context, req any) (any, error) {
		return srv.(proxyIngestGRPCService).CompleteDependencyGraphResolve(ctx, req.(*CompleteDependencyGraphResolveRequest))
	}
	return interceptor(ctx, req, info, handler)
}

func (s *Server) failDependencyGraphResolveHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	req := &FailDependencyGraphResolveRequest{}
	if err := dec(req); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(proxyIngestGRPCService).FailDependencyGraphResolve(ctx, req)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/" + serviceName + "/FailDependencyGraphResolve"}
	handler := func(ctx context.Context, req any) (any, error) {
		return srv.(proxyIngestGRPCService).FailDependencyGraphResolve(ctx, req.(*FailDependencyGraphResolveRequest))
	}
	return interceptor(ctx, req, info, handler)
}

func (s *Server) lookupDependencyGraphContextHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	req := &LookupDependencyGraphContextRequest{}
	if err := dec(req); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(proxyIngestGRPCService).LookupDependencyGraphContext(ctx, req)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/" + serviceName + "/LookupDependencyGraphContext"}
	handler := func(ctx context.Context, req any) (any, error) {
		return srv.(proxyIngestGRPCService).LookupDependencyGraphContext(ctx, req.(*LookupDependencyGraphContextRequest))
	}
	return interceptor(ctx, req, info, handler)
}

func (s *Server) watchDependencyGraphResolveHandler(srv any, stream grpc.ServerStream) error {
	req := &WatchDependencyGraphResolveRequest{}
	if err := stream.RecvMsg(req); err != nil {
		return err
	}
	notifications, err := srv.(proxyIngestGRPCService).WatchDependencyGraphResolve(stream.Context())
	if err != nil {
		return err
	}
	for {
		select {
		case <-stream.Context().Done():
			return nil
		case _, ok := <-notifications:
			if !ok {
				return nil
			}
			if err := stream.SendMsg(&DependencyGraphResolveQueuedEvent{}); err != nil {
				return err
			}
		}
	}
}
