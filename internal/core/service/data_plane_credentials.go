package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/danielterry/dependency-firewall/internal/core/port"
)

// CredentialSecret is returned only at creation time. Callers must not persist
// or log it after presenting it to the operator.
type CredentialSecret struct {
	Credential domain.DataPlaneCredential
	Secret     string
}

type DataPlaneCredentialService struct {
	repository port.DataPlaneCredentialRepository
}

func NewDataPlaneCredentialService(repository port.DataPlaneCredentialRepository) (*DataPlaneCredentialService, error) {
	if repository == nil {
		return nil, fmt.Errorf("data-plane credential repository is required")
	}
	return &DataPlaneCredentialService{repository: repository}, nil
}

func (s *DataPlaneCredentialService) Create(ctx context.Context, credential domain.DataPlaneCredential) (*CredentialSecret, error) {
	if strings.TrimSpace(credential.Name) == "" || credential.TenantID == "" || credential.OrganizationID == "" || credential.CreatedBy == "" {
		return nil, fmt.Errorf("credential name, tenant, organization, and creator are required")
	}
	if credential.ExpiresAt != nil && !credential.ExpiresAt.After(time.Now()) {
		return nil, fmt.Errorf("credential expiry must be in the future")
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, fmt.Errorf("generating credential secret: %w", err)
	}
	secret := base64.RawURLEncoding.EncodeToString(raw)
	hash := sha256.Sum256([]byte(secret))
	credential.SecretDigest = hex.EncodeToString(hash[:])
	if err := s.repository.Create(ctx, &credential); err != nil {
		return nil, err
	}
	return &CredentialSecret{Credential: credential, Secret: secret}, nil
}

// Verify compares an opaque presented secret with a bundle verifier digest.
func VerifyCredentialSecret(secret string, verifier domain.DataPlaneCredentialVerifier, now time.Time) bool {
	if secret == "" || verifier.SecretDigest == "" || verifier.RevokedAt != nil || (verifier.ExpiresAt != nil && !verifier.ExpiresAt.After(now)) {
		return false
	}
	h := sha256.Sum256([]byte(secret))
	return subtleConstantTimeEqual(hex.EncodeToString(h[:]), verifier.SecretDigest)
}

func subtleConstantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
