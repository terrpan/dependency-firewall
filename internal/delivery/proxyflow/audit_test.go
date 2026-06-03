package proxyflow

import (
	"context"
	"testing"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type auditRecorderStub struct {
	events []domain.AuditEvent
}

func (s *auditRecorderStub) Record(_ context.Context, event domain.AuditEvent) error {
	s.events = append(s.events, event)
	return nil
}

func TestRecordRequestDenied_IncludesTopReasonAndReasons(t *testing.T) {
	recorder := &auditRecorderStub{}
	audit := AuditContext{
		TenantID:      "tenant-1",
		CorrelationID: "corr-1",
		Source:        "proxy",
		UpstreamID:    "up-1",
		Operation:     "metadata",
		Artifact: domain.ArtifactIdentity{
			Ecosystem: domain.EcosystemNPM,
			Name:      "left-pad",
			Version:   "1.3.0",
		},
	}
	decision := &domain.Decision{
		ID:       "dec-1",
		PolicyID: "policy-1",
		Outcome:  domain.DecisionDeny,
		Reason:   "artifact has vulnerability with severity high at or above threshold moderate",
		Reasons: []domain.EvaluationReason{
			{PolicyID: "policy-1", PolicyName: "vuln-threshold", Action: domain.PolicyActionDeny, Message: "severity high >= moderate"},
			{PolicyID: "policy-2", PolicyName: "cvss-threshold", Action: domain.PolicyActionDeny, Message: "cvss 9.1 >= 7.0"},
		},
	}

	err := RecordRequestDenied(context.Background(), recorder, audit, decision, "request denied")
	require.NoError(t, err)
	require.Len(t, recorder.events, 1)

	event := recorder.events[0]
	assert.Equal(t, domain.AuditEventRequestDenied, event.EventType)
	assert.Equal(t, "request denied", event.Message)
	assert.Equal(t, decision.Reason, event.Payload["reason"])
	reasons, ok := event.Payload["reasons"].([]domain.EvaluationReason)
	require.True(t, ok)
	require.Len(t, reasons, 2)
	assert.Equal(t, "severity high >= moderate", reasons[0].Message)
}

func TestRecordRequestAllowed_IncludesWarningsAndReasons(t *testing.T) {
	recorder := &auditRecorderStub{}
	audit := AuditContext{
		TenantID:      "tenant-1",
		CorrelationID: "corr-2",
		Source:        "proxy",
		UpstreamID:    "up-1",
		Operation:     "content",
		Artifact: domain.ArtifactIdentity{
			Ecosystem: domain.EcosystemNPM,
			Name:      "left-pad",
			Version:   "1.3.0",
		},
	}
	decision := &domain.Decision{
		ID:       "dec-2",
		PolicyID: "policy-3",
		Outcome:  domain.DecisionAllow,
		Reason:   "no matching policy",
		Warnings: []string{"[vuln-threshold] severity high >= moderate"},
		Reasons: []domain.EvaluationReason{
			{PolicyID: "policy-3", PolicyName: "vuln-threshold", Action: domain.PolicyActionDeny, Category: domain.ReasonPolicyWarning, Message: "severity high >= moderate"},
		},
	}

	err := RecordRequestAllowed(context.Background(), recorder, audit, decision, "request allowed")
	require.NoError(t, err)
	require.Len(t, recorder.events, 1)

	event := recorder.events[0]
	assert.Equal(t, domain.AuditEventRequestAllowed, event.EventType)
	assert.Equal(t, "request allowed", event.Message)
	warnings, ok := event.Payload["warnings"].([]string)
	require.True(t, ok)
	require.Len(t, warnings, 1)
	reasons, ok := event.Payload["reasons"].([]domain.EvaluationReason)
	require.True(t, ok)
	require.Len(t, reasons, 1)
	assert.Equal(t, "severity high >= moderate", reasons[0].Message)
}

func TestRecordRequestForwarded_DoesNotAttachDecisionEntityOrOutcome(t *testing.T) {
	recorder := &auditRecorderStub{}
	audit := AuditContext{
		TenantID:      "tenant-1",
		CorrelationID: "corr-3",
		Source:        "proxy",
		UpstreamID:    "up-1",
		Operation:     "metadata",
		Artifact: domain.ArtifactIdentity{
			Ecosystem: domain.EcosystemNPM,
			Name:      "left-pad",
		},
	}
	decision := &domain.Decision{
		ID:      "dec-3",
		Outcome: domain.DecisionAllow,
		Reason:  "no matching policy",
		Artifact: domain.ArtifactIdentity{
			Ecosystem: domain.EcosystemNPM,
			Name:      "left-pad",
		},
		Reasons: []domain.EvaluationReason{
			{Category: domain.ReasonNoMatchingPolicy, Message: "no matching policy"},
		},
	}

	err := RecordRequestForwarded(context.Background(), recorder, audit, decision, "bare npm packument", "request forwarded")
	require.NoError(t, err)
	require.Len(t, recorder.events, 1)

	event := recorder.events[0]
	assert.Equal(t, domain.AuditEventRequestForwarded, event.EventType)
	assert.Equal(t, "request forwarded", event.Message)
	assert.Empty(t, event.EntityType)
	assert.Empty(t, event.EntityID)
	assert.Empty(t, event.Outcome)
	assert.Equal(t, "bare npm packument", event.Payload["reason"])
	assert.Equal(t, domain.DecisionAllow, event.Payload["evaluation_outcome"])
	reasons, ok := event.Payload["reasons"].([]domain.EvaluationReason)
	require.True(t, ok)
	require.Len(t, reasons, 1)
}
