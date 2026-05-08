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
