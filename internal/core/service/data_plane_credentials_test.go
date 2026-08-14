package service

import (
	"context"
	"testing"
	"time"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/stretchr/testify/require"
)

type credentialRepoStub struct{ created *domain.DataPlaneCredential }

func (r *credentialRepoStub) Create(_ context.Context, c *domain.DataPlaneCredential) error {
	c.ID = "id"
	r.created = c
	return nil
}
func (*credentialRepoStub) GetByID(context.Context, string, string) (*domain.DataPlaneCredential, error) {
	return nil, domain.ErrCredentialNotFound
}
func (*credentialRepoStub) ListByScope(context.Context, string, string, string) ([]domain.DataPlaneCredential, error) {
	return nil, nil
}
func (*credentialRepoStub) ListVerifiersByTenant(context.Context, string) ([]domain.DataPlaneCredentialVerifier, error) {
	return nil, nil
}
func (*credentialRepoStub) Revoke(context.Context, string, string, time.Time) error { return nil }

func TestDataPlaneCredentialCreateHashesSecretAndVerify(t *testing.T) {
	repo := &credentialRepoStub{}
	svc, err := NewDataPlaneCredentialService(repo)
	require.NoError(t, err)
	result, err := svc.Create(context.Background(), domain.DataPlaneCredential{TenantID: "t", OrganizationID: "o", Name: "npm", CreatedBy: "p"})
	require.NoError(t, err)
	require.NotEmpty(t, result.Secret)
	require.NotEqual(t, result.Secret, result.Credential.SecretDigest)
	v := domain.DataPlaneCredentialVerifier{TenantID: "t", OrganizationID: "o", SecretDigest: result.Credential.SecretDigest}
	require.True(t, VerifyCredentialSecret(result.Secret, v, time.Now()))
	require.False(t, VerifyCredentialSecret("wrong", v, time.Now()))
}

func TestDataPlaneCredentialVerifyRejectsExpiredAndRevoked(t *testing.T) {
	now := time.Now()
	v := domain.DataPlaneCredentialVerifier{SecretDigest: "bad", ExpiresAt: func() *time.Time { x := now.Add(-time.Minute); return &x }()}
	require.False(t, VerifyCredentialSecret("x", v, now))
	if v.ExpiresAt != nil {
		v.ExpiresAt = nil
	}
	v.RevokedAt = &now
	require.False(t, VerifyCredentialSecret("x", v, now))
}
