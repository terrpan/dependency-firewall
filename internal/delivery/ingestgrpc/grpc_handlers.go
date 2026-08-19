package ingestgrpc

import (
	"context"

	"google.golang.org/grpc"
)

func dispatchUnary[Request, Response any](
	srv any,
	ctx context.Context,
	dec func(any) error,
	interceptor grpc.UnaryServerInterceptor,
	methodName string,
	invoke func(proxyIngestGRPCService, context.Context, *Request) (*Response, error),
) (any, error) {
	req := new(Request)
	if err := dec(req); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return invoke(srv.(proxyIngestGRPCService), ctx, req)
	}

	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/" + serviceName + "/" + methodName}
	handler := func(ctx context.Context, rawRequest any) (any, error) {
		return invoke(srv.(proxyIngestGRPCService), ctx, rawRequest.(*Request))
	}
	return interceptor(ctx, req, info, handler)
}

func (s *Server) recordDecisionHandler(
	srv any,
	ctx context.Context,
	dec func(any) error,
	interceptor grpc.UnaryServerInterceptor,
) (any, error) {
	return dispatchUnary(srv, ctx, dec, interceptor, "RecordDecision", proxyIngestGRPCService.RecordDecision)
}

func (s *Server) getDecisionByArtifactHandler(
	srv any,
	ctx context.Context,
	dec func(any) error,
	interceptor grpc.UnaryServerInterceptor,
) (any, error) {
	return dispatchUnary(
		srv,
		ctx,
		dec,
		interceptor,
		"GetDecisionByArtifact",
		proxyIngestGRPCService.GetDecisionByArtifact,
	)
}

func (s *Server) listDecisionsByTenantHandler(
	srv any,
	ctx context.Context,
	dec func(any) error,
	interceptor grpc.UnaryServerInterceptor,
) (any, error) {
	return dispatchUnary(
		srv,
		ctx,
		dec,
		interceptor,
		"ListDecisionsByTenant",
		proxyIngestGRPCService.ListDecisionsByTenant,
	)
}

func (s *Server) hasRecentAllowHandler(
	srv any,
	ctx context.Context,
	dec func(any) error,
	interceptor grpc.UnaryServerInterceptor,
) (any, error) {
	return dispatchUnary(srv, ctx, dec, interceptor, "HasRecentAllow", proxyIngestGRPCService.HasRecentAllow)
}

func (s *Server) recordAuditEventHandler(
	srv any,
	ctx context.Context,
	dec func(any) error,
	interceptor grpc.UnaryServerInterceptor,
) (any, error) {
	return dispatchUnary(srv, ctx, dec, interceptor, "RecordAuditEvent", proxyIngestGRPCService.RecordAuditEvent)
}

func (s *Server) enqueueDependencyGraphResolveHandler(
	srv any,
	ctx context.Context,
	dec func(any) error,
	interceptor grpc.UnaryServerInterceptor,
) (any, error) {
	return dispatchUnary(
		srv,
		ctx,
		dec,
		interceptor,
		"EnqueueDependencyGraphResolve",
		proxyIngestGRPCService.EnqueueDependencyGraphResolve,
	)
}

func (s *Server) claimDependencyGraphResolveHandler(
	srv any,
	ctx context.Context,
	dec func(any) error,
	interceptor grpc.UnaryServerInterceptor,
) (any, error) {
	return dispatchUnary(
		srv,
		ctx,
		dec,
		interceptor,
		"ClaimDependencyGraphResolve",
		proxyIngestGRPCService.ClaimDependencyGraphResolve,
	)
}

func (s *Server) completeDependencyGraphResolveHandler(
	srv any,
	ctx context.Context,
	dec func(any) error,
	interceptor grpc.UnaryServerInterceptor,
) (any, error) {
	return dispatchUnary(
		srv,
		ctx,
		dec,
		interceptor,
		"CompleteDependencyGraphResolve",
		proxyIngestGRPCService.CompleteDependencyGraphResolve,
	)
}

func (s *Server) failDependencyGraphResolveHandler(
	srv any,
	ctx context.Context,
	dec func(any) error,
	interceptor grpc.UnaryServerInterceptor,
) (any, error) {
	return dispatchUnary(
		srv,
		ctx,
		dec,
		interceptor,
		"FailDependencyGraphResolve",
		proxyIngestGRPCService.FailDependencyGraphResolve,
	)
}

func (s *Server) lookupDependencyGraphContextHandler(
	srv any,
	ctx context.Context,
	dec func(any) error,
	interceptor grpc.UnaryServerInterceptor,
) (any, error) {
	return dispatchUnary(
		srv,
		ctx,
		dec,
		interceptor,
		"LookupDependencyGraphContext",
		proxyIngestGRPCService.LookupDependencyGraphContext,
	)
}

func (s *Server) watchDependencyGraphResolveHandler(srv any, stream grpc.ServerStream) error {
	req := &WatchDependencyGraphResolveRequest{}
	if err := stream.RecvMsg(req); err != nil {
		return err
	}
	notifications, err := srv.(proxyIngestGRPCService).WatchDependencyGraphResolve(stream.Context(), req)
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
