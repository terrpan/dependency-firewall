// Package secrets provides small secret-handling primitives for infrastructure adapters.
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
)

const (
	envelopeVersion = 1
	aes256KeySize   = 32
)

// Codec encrypts and decrypts small secret payloads.
type Codec interface {
	Encrypt(plaintext []byte) ([]byte, error)
	Decrypt(payload []byte) ([]byte, error)
}

// AESGCMCodec encrypts secret payloads with AES-256-GCM.
type AESGCMCodec struct {
	aead cipher.AEAD
}

type envelope struct {
	Version    int    `json:"version"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

// NewAESGCMCodec creates an AES-256-GCM codec from a raw 32-byte key.
func NewAESGCMCodec(key []byte) (*AESGCMCodec, error) {
	if len(key) != aes256KeySize {
		return nil, fmt.Errorf("secret key must be %d bytes", aes256KeySize)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating aes cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating gcm cipher: %w", err)
	}
	return &AESGCMCodec{aead: aead}, nil
}

// NewAESGCMCodecFromBase64 creates an AES-256-GCM codec from a base64 encoded 32-byte key.
func NewAESGCMCodecFromBase64(encoded string) (*AESGCMCodec, error) {
	key, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decoding secret key: %w", err)
	}
	return NewAESGCMCodec(key)
}

// Encrypt encrypts plaintext and returns a JSON envelope.
func (c *AESGCMCodec) Encrypt(plaintext []byte) ([]byte, error) {
	if c == nil {
		return nil, fmt.Errorf("secret codec is not configured")
	}

	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generating secret nonce: %w", err)
	}

	ciphertext := c.aead.Seal(nil, nonce, plaintext, nil)
	payload, err := json.Marshal(envelope{
		Version:    envelopeVersion,
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	})
	if err != nil {
		return nil, fmt.Errorf("marshalling secret envelope: %w", err)
	}
	return payload, nil
}

// Decrypt decrypts a JSON envelope returned by Encrypt.
func (c *AESGCMCodec) Decrypt(payload []byte) ([]byte, error) {
	if c == nil {
		return nil, fmt.Errorf("secret codec is not configured")
	}

	var env envelope
	if err := json.Unmarshal(payload, &env); err != nil {
		return nil, fmt.Errorf("unmarshalling secret envelope: %w", err)
	}
	if env.Version != envelopeVersion {
		return nil, fmt.Errorf("unsupported secret envelope version %d", env.Version)
	}

	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil {
		return nil, fmt.Errorf("decoding secret nonce: %w", err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(env.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decoding secret ciphertext: %w", err)
	}

	plaintext, err := c.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypting secret: %w", err)
	}
	return plaintext, nil
}
