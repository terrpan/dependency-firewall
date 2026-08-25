package middleware

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

func TestPrincipalFromContext(t *testing.T) {
	t.Parallel()
	principal := domain.AuthenticatedPrincipal{
		Ref:         domain.PrincipalRef{Issuer: "https://issuer.example/Exact", Subject: " Subject 42 "},
		DisplayName: "Operator",
		Email:       "operator@example.com",
	}

	got, ok := PrincipalFromContext(ContextWithPrincipal(context.Background(), principal))

	assert.True(t, ok)
	assert.Equal(t, principal, got)
}

func TestPrincipalFromContextRejectsIncompleteIdentity(t *testing.T) {
	t.Parallel()
	_, ok := PrincipalFromContext(ContextWithPrincipal(context.Background(), domain.AuthenticatedPrincipal{
		Ref: domain.PrincipalRef{Issuer: "https://issuer.example"},
	}))
	assert.False(t, ok)
}
