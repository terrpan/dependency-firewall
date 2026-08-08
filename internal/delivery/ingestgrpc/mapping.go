package ingestgrpc

import (
	"github.com/danielterry/dependency-firewall/internal/core/domain"
	wire "github.com/danielterry/dependency-firewall/internal/wire/ingestgrpc"
)

func fromDomainDecision(decision *domain.Decision) Decision {
	return wire.FromDomainDecision(decision)
}

func fromDomainArtifactIdentity(artifact domain.ArtifactIdentity) ArtifactIdentity {
	return wire.FromDomainArtifactIdentity(artifact)
}

func fromDomainUpstream(upstream domain.Upstream) Upstream {
	return wire.FromDomainUpstream(upstream)
}

func fromDomainAuditEvent(event *domain.AuditEvent) AuditEvent {
	return wire.FromDomainAuditEvent(event)
}
