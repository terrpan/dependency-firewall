package secrets

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAESGCMCodecEncryptDecrypt(t *testing.T) {
	t.Parallel()

	key := []byte("0123456789abcdef0123456789abcdef")
	codec, err := NewAESGCMCodec(key)
	require.NoError(t, err)

	payload, err := codec.Encrypt([]byte("registry-token"))
	require.NoError(t, err)
	assert.NotContains(t, string(payload), "registry-token")

	plaintext, err := codec.Decrypt(payload)
	require.NoError(t, err)
	assert.Equal(t, "registry-token", string(plaintext))
}

func TestAESGCMCodecRejectsInvalidPayloads(t *testing.T) {
	t.Parallel()

	codec, err := NewAESGCMCodec([]byte("0123456789abcdef0123456789abcdef"))
	require.NoError(t, err)

	tests := map[string][]byte{
		"tampered json": []byte(`{"version":1,"nonce":"bad","ciphertext":"bad"}`),
		"bad version":   []byte(`{"version":99,"nonce":"","ciphertext":""}`),
	}

	for name, payload := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := codec.Decrypt(payload)
			require.Error(t, err)
		})
	}
}

func TestAESGCMCodecRejectsWrongKey(t *testing.T) {
	t.Parallel()

	codec, err := NewAESGCMCodec([]byte("0123456789abcdef0123456789abcdef"))
	require.NoError(t, err)
	payload, err := codec.Encrypt([]byte("registry-token"))
	require.NoError(t, err)

	wrongCodec, err := NewAESGCMCodec([]byte("abcdef0123456789abcdef0123456789"))
	require.NoError(t, err)

	_, err = wrongCodec.Decrypt(payload)
	require.Error(t, err)
}

func TestNewAESGCMCodecFromBase64ValidatesKey(t *testing.T) {
	t.Parallel()

	_, err := NewAESGCMCodecFromBase64("not-base64")
	require.Error(t, err)

	shortKey := base64.StdEncoding.EncodeToString([]byte("short"))
	_, err = NewAESGCMCodecFromBase64(shortKey)
	require.Error(t, err)
}
