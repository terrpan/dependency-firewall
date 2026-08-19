package secrets

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHybridEncryptDecrypt(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		privateKey func(t *testing.T) any
		publicKey  func(any) any
		wantAlg    string
	}{
		{
			name: "rsa",
			privateKey: func(t *testing.T) any {
				key, err := rsa.GenerateKey(rand.Reader, 2048)
				require.NoError(t, err)
				return key
			},
			publicKey: func(key any) any {
				return &key.(*rsa.PrivateKey).PublicKey
			},
			wantAlg: AlgRSAOAEPAES256GCM,
		},
		{
			name: "p256",
			privateKey: func(t *testing.T) any {
				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)
				return key
			},
			publicKey: func(key any) any {
				return &key.(*ecdsa.PrivateKey).PublicKey
			},
			wantAlg: AlgECIESP256AES256GCM,
		},
		{
			name: "p384",
			privateKey: func(t *testing.T) any {
				key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				require.NoError(t, err)
				return key
			},
			publicKey: func(key any) any {
				return &key.(*ecdsa.PrivateKey).PublicKey
			},
			wantAlg: AlgECIESP384AES256GCM,
		},
		{
			name: "p521",
			privateKey: func(t *testing.T) any {
				key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
				require.NoError(t, err)
				return key
			},
			publicKey: func(key any) any {
				return &key.(*ecdsa.PrivateKey).PublicKey
			},
			wantAlg: AlgECIESP521AES256GCM,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			privateKey := tt.privateKey(t)
			payload, err := EncryptForPublicKey(tt.publicKey(privateKey), []byte("registry-token"))
			require.NoError(t, err)
			assert.NotContains(t, string(payload), "registry-token")
			assert.True(t, IsHybridEnvelope(payload))

			var env HybridEnvelope
			require.NoError(t, json.Unmarshal(payload, &env))
			assert.Equal(t, HybridEnvelopeVersion, env.Version)
			assert.Equal(t, tt.wantAlg, env.Alg)

			plaintext, err := DecryptWithPrivateKey(privateKey, payload)
			require.NoError(t, err)
			assert.Equal(t, "registry-token", string(plaintext))
		})
	}
}

func TestHybridDecryptRejectsWrongKey(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	payload, err := EncryptForPublicKey(&privateKey.PublicKey, []byte("registry-token"))
	require.NoError(t, err)

	_, err = DecryptWithPrivateKey(wrongKey, payload)
	require.Error(t, err)
}

func TestIsHybridEnvelopeRejectsLegacyPlaintext(t *testing.T) {
	t.Parallel()

	assert.False(t, IsHybridEnvelope([]byte("registry-token")))
	assert.False(t, IsHybridEnvelope([]byte(`{"version":1,"nonce":"abc","ciphertext":"def"}`)))
	assert.False(t, IsHybridEnvelope([]byte(`{"version":2,"alg":"unknown","nonce":"abc","ciphertext":"def"}`)))
	assert.False(
		t,
		IsHybridEnvelope([]byte(`{"version":2,"alg":"ecies-p256-aes256gcm","nonce":"abc","ciphertext":"def"}`)),
	)
	assert.False(
		t,
		IsHybridEnvelope(
			[]byte(`{"version":2,"alg":"rsa-oaep-aes256gcm","ephemeral_pub":"abc","nonce":"abc","ciphertext":"def"}`),
		),
	)
	assert.False(
		t,
		IsHybridEnvelope(
			[]byte(`{"version":3,"alg":"rsa-oaep-aes256gcm","encrypted_key":"abc","nonce":"abc","ciphertext":"def"}`),
		),
	)
	assert.True(
		t,
		IsHybridEnvelope(
			[]byte(`{"version":2,"alg":"rsa-oaep-aes256gcm","encrypted_key":"abc","nonce":"abc","ciphertext":"def"}`),
		),
	)
}

func TestDecryptRejectsNonMatchingVersion(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	_, err = DecryptWithPrivateKey(
		privateKey,
		[]byte(`{"version":1,"alg":"rsa-oaep-aes256gcm","encrypted_key":"abc","nonce":"abc","ciphertext":"def"}`),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "version")

	_, err = DecryptWithPrivateKey(
		privateKey,
		[]byte(`{"version":3,"alg":"rsa-oaep-aes256gcm","encrypted_key":"abc","nonce":"abc","ciphertext":"def"}`),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "version")
}

func TestHybridPrivateKeyResolverPreservesLegacyPlaintext(t *testing.T) {
	t.Parallel()

	resolver := NewHybridPrivateKeyResolver(nil)
	secret, err := resolver.ResolveSecret([]byte("registry-token"))
	require.NoError(t, err)
	assert.Equal(t, "registry-token", string(secret))
}

func TestStrictHybridPrivateKeyResolverRejectsLegacyPlaintext(t *testing.T) {
	t.Parallel()

	resolver := NewStrictHybridPrivateKeyResolver(nil)
	_, err := resolver.ResolveSecret([]byte("registry-token"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "hybrid secret envelope is required")
}

func TestStrictHybridPrivateKeyResolverDecryptsEnvelope(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	payload, err := EncryptForPublicKey(&privateKey.PublicKey, []byte("registry-token"))
	require.NoError(t, err)

	resolver := NewStrictHybridPrivateKeyResolver(privateKey)
	secret, err := resolver.ResolveSecret(payload)
	require.NoError(t, err)
	assert.Equal(t, "registry-token", string(secret))
}
