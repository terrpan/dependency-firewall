package service

import (
	"context"
	"errors"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

const serviceTracerName = "github.com/danielterry/dependency-firewall/internal/core/service"

func serviceTracer() trace.Tracer {
	return otel.Tracer(serviceTracerName)
}

func accessRequestAttributes(req domain.AccessRequest) []attribute.KeyValue {
	attrs := []attribute.KeyValue{
		attribute.String("tenant.id", req.TenantID),
		attribute.String("artifact.ecosystem", string(req.Artifact.Ecosystem)),
		attribute.String("artifact.reference_type", artifactReferenceType(req.Artifact)),
		attribute.Bool("artifact.has_digest", req.Artifact.Digest != ""),
	}
	if req.RequestID != "" {
		attrs = append(attrs, attribute.String("request.id", req.RequestID))
	}
	if req.Upstream.ID != "" {
		attrs = append(attrs, attribute.String("upstream.id", req.Upstream.ID))
	}
	return attrs
}

func artifactReferenceType(artifact domain.ArtifactIdentity) string {
	switch {
	case artifact.Digest != "":
		return "digest"
	case artifact.Version != "":
		if artifact.IsMutableReference() {
			return "mutable"
		}
		return "version"
	default:
		return "name"
	}
}

func recordSpanError(span trace.Span, err error) {
	if err == nil || span == nil {
		return
	}
	span.RecordError(err)
	span.SetStatus(codes.Error, err.Error())
}

func recordSpanErrorIfUnexpected(span trace.Span, err error) {
	if err == nil || isExpectedSpanOutcome(err) {
		return
	}
	recordSpanError(span, err)
}

func isExpectedSpanOutcome(err error) bool {
	if err == nil {
		return false
	}
	expectedOutcomes := [...]error{
		context.Canceled,
		domain.ErrCacheMiss,
		domain.ErrPolicyViolation,
		domain.ErrArtifactNotFound,
		domain.ErrTenantNotFound,
		domain.ErrPolicyNotFound,
		domain.ErrUpstreamNotFound,
		domain.ErrPolicyVersionNotFound,
		domain.ErrTenantNameConflict,
		domain.ErrPolicyNameConflict,
		domain.ErrUpstreamNameConflict,
		domain.ErrUpstreamRegistryConflict,
		domain.ErrPolicyDeleteEnabled,
		domain.ErrPolicyInUse,
		domain.ErrUpstreamInUse,
		domain.ErrInvalidPolicy,
		domain.ErrPolicyUpstreamIncompatible,
		domain.ErrUnsupportedUpstreamCapability,
		domain.ErrUpstreamPolicyConflict,
	}
	for _, expected := range expectedOutcomes {
		if errors.Is(err, expected) {
			return true
		}
	}
	return false
}
