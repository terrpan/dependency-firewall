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
	switch {
	case errors.Is(err, context.Canceled):
		return true
	case errors.Is(err, domain.ErrCacheMiss):
		return true
	case errors.Is(err, domain.ErrPolicyViolation):
		return true
	case errors.Is(err, domain.ErrArtifactNotFound):
		return true
	case errors.Is(err, domain.ErrTenantNotFound):
		return true
	case errors.Is(err, domain.ErrPolicyNotFound):
		return true
	case errors.Is(err, domain.ErrUpstreamNotFound):
		return true
	case errors.Is(err, domain.ErrPolicyVersionNotFound):
		return true
	case errors.Is(err, domain.ErrTenantNameConflict):
		return true
	case errors.Is(err, domain.ErrPolicyNameConflict):
		return true
	case errors.Is(err, domain.ErrUpstreamNameConflict):
		return true
	case errors.Is(err, domain.ErrUpstreamRegistryConflict):
		return true
	case errors.Is(err, domain.ErrPolicyDeleteEnabled):
		return true
	case errors.Is(err, domain.ErrPolicyInUse):
		return true
	case errors.Is(err, domain.ErrUpstreamInUse):
		return true
	case errors.Is(err, domain.ErrInvalidPolicy):
		return true
	case errors.Is(err, domain.ErrPolicyUpstreamIncompatible):
		return true
	case errors.Is(err, domain.ErrUnsupportedUpstreamCapability):
		return true
	case errors.Is(err, domain.ErrUpstreamPolicyConflict):
		return true
	default:
		return false
	}
}
