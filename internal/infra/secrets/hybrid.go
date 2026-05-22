package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	HybridEnvelopeVersion = 2

	AlgECIESP256AES256GCM = "ecies-p256-aes256gcm"
	AlgECIESP384AES256GCM = "ecies-p384-aes256gcm"
	AlgECIESP521AES256GCM = "ecies-p521-aes256gcm"
	AlgRSAOAEPAES256GCM   = "rsa-oaep-aes256gcm"
)

var hybridHKDFInfo = []byte("dependency-firewall bundle upstream auth v2")

// HybridEnvelope carries an upstream auth secret encrypted for one proxy.
type HybridEnvelope struct {
	Version      int    `json:"version"`
	Alg          string `json:"alg"`
	EphemeralPub string `json:"ephemeral_pub,omitempty"`
	EncryptedKey string `json:"encrypted_key,omitempty"`
	Nonce        string `json:"nonce"`
	Ciphertext   string `json:"ciphertext"`
}

// EncryptForPublicKey encrypts plaintext for an RSA or NIST EC public key.
func EncryptForPublicKey(publicKey any, plaintext []byte) ([]byte, error) {
	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		return encryptRSA(key, plaintext)
	case *ecdsa.PublicKey:
		return encryptEC(key, plaintext)
	default:
		return nil, fmt.Errorf("unsupported public key type %T", publicKey)
	}
}

// DecryptWithPrivateKey decrypts a hybrid envelope with an RSA or NIST EC private key.
func DecryptWithPrivateKey(privateKey any, payload []byte) ([]byte, error) {
	var env HybridEnvelope
	if err := json.Unmarshal(payload, &env); err != nil {
		return nil, fmt.Errorf("unmarshalling hybrid secret envelope: %w", err)
	}
	if env.Version != HybridEnvelopeVersion {
		return nil, fmt.Errorf("unsupported hybrid secret envelope version %d (expected %d)", env.Version, HybridEnvelopeVersion)
	}
	if !isWellFormedHybridEnvelope(env) {
		return nil, fmt.Errorf("invalid hybrid secret envelope")
	}

	switch env.Alg {
	case AlgRSAOAEPAES256GCM:
		key, ok := privateKey.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("rsa hybrid envelope requires rsa private key")
		}
		return decryptRSA(key, env)
	case AlgECIESP256AES256GCM, AlgECIESP384AES256GCM, AlgECIESP521AES256GCM:
		key, ok := privateKey.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("ec hybrid envelope requires ecdsa private key")
		}
		return decryptEC(key, env)
	default:
		return nil, fmt.Errorf("unsupported hybrid secret algorithm %q", env.Alg)
	}
}

// IsHybridEnvelope reports whether payload looks like a version-2 encrypted
// bundle secret envelope.
func IsHybridEnvelope(payload []byte) bool {
	var env HybridEnvelope
	if err := json.Unmarshal(payload, &env); err != nil {
		return false
	}
	return env.Version == HybridEnvelopeVersion && isWellFormedHybridEnvelope(env)
}

func isWellFormedHybridEnvelope(env HybridEnvelope) bool {
	if env.Alg == "" || env.Nonce == "" || env.Ciphertext == "" {
		return false
	}

	switch env.Alg {
	case AlgRSAOAEPAES256GCM:
		return env.EncryptedKey != "" && env.EphemeralPub == ""
	case AlgECIESP256AES256GCM, AlgECIESP384AES256GCM, AlgECIESP521AES256GCM:
		return env.EphemeralPub != "" && env.EncryptedKey == ""
	default:
		return false
	}
}

// HybridPrivateKeyResolver decrypts hybrid envelopes with a process-local private key.
type HybridPrivateKeyResolver struct {
	privateKey any
	strict     bool
}

// NewHybridPrivateKeyResolver creates a resolver for version-2 hybrid envelopes.
func NewHybridPrivateKeyResolver(privateKey any) *HybridPrivateKeyResolver {
	return &HybridPrivateKeyResolver{privateKey: privateKey}
}

// NewStrictHybridPrivateKeyResolver creates a resolver that requires version-2 hybrid envelopes.
func NewStrictHybridPrivateKeyResolver(privateKey any) *HybridPrivateKeyResolver {
	return &HybridPrivateKeyResolver{privateKey: privateKey, strict: true}
}

// ResolveSecret decrypts encrypted envelopes and returns legacy plaintext unchanged.
func (r *HybridPrivateKeyResolver) ResolveSecret(payload []byte) ([]byte, error) {
	if !IsHybridEnvelope(payload) {
		if r != nil && r.strict {
			return nil, fmt.Errorf("hybrid secret envelope is required")
		}
		return append([]byte(nil), payload...), nil
	}
	if r == nil || r.privateKey == nil {
		return nil, fmt.Errorf("hybrid private key resolver is not configured")
	}
	return DecryptWithPrivateKey(r.privateKey, payload)
}

func encryptRSA(publicKey *rsa.PublicKey, plaintext []byte) ([]byte, error) {
	sessionKey := make([]byte, aes256KeySize)
	if _, err := io.ReadFull(rand.Reader, sessionKey); err != nil {
		return nil, fmt.Errorf("generating rsa hybrid session key: %w", err)
	}
	defer clearBytes(sessionKey)

	encryptedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, sessionKey, hybridHKDFInfo)
	if err != nil {
		return nil, fmt.Errorf("encrypting rsa hybrid session key: %w", err)
	}

	nonce, ciphertext, err := encryptAESGCM(sessionKey, plaintext)
	if err != nil {
		return nil, err
	}
	return marshalHybridEnvelope(HybridEnvelope{
		Version:      HybridEnvelopeVersion,
		Alg:          AlgRSAOAEPAES256GCM,
		EncryptedKey: base64.StdEncoding.EncodeToString(encryptedKey),
		Nonce:        base64.StdEncoding.EncodeToString(nonce),
		Ciphertext:   base64.StdEncoding.EncodeToString(ciphertext),
	})
}

func decryptRSA(privateKey *rsa.PrivateKey, env HybridEnvelope) ([]byte, error) {
	encryptedKey, err := base64.StdEncoding.DecodeString(env.EncryptedKey)
	if err != nil {
		return nil, fmt.Errorf("decoding rsa hybrid encrypted key: %w", err)
	}
	sessionKey, err := rsa.DecryptOAEP(sha256.New(), nil, privateKey, encryptedKey, hybridHKDFInfo)
	if err != nil {
		return nil, fmt.Errorf("decrypting rsa hybrid session key: %w", err)
	}
	defer clearBytes(sessionKey)

	return decryptAESGCM(sessionKey, env.Nonce, env.Ciphertext)
}

func encryptEC(publicKey *ecdsa.PublicKey, plaintext []byte) ([]byte, error) {
	curve, alg, err := ecdhCurveForPublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	peerPublicKey, err := publicKey.ECDH()
	if err != nil {
		return nil, fmt.Errorf("converting peer public key to ecdh: %w", err)
	}
	ephemeralPrivateKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating ephemeral ecdh key: %w", err)
	}
	sharedSecret, err := ephemeralPrivateKey.ECDH(peerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("computing ecdh shared secret: %w", err)
	}
	defer clearBytes(sharedSecret)

	sessionKey, err := deriveHybridKey(sharedSecret)
	if err != nil {
		return nil, err
	}
	defer clearBytes(sessionKey)

	nonce, ciphertext, err := encryptAESGCM(sessionKey, plaintext)
	if err != nil {
		return nil, err
	}
	return marshalHybridEnvelope(HybridEnvelope{
		Version:      HybridEnvelopeVersion,
		Alg:          alg,
		EphemeralPub: base64.StdEncoding.EncodeToString(ephemeralPrivateKey.PublicKey().Bytes()),
		Nonce:        base64.StdEncoding.EncodeToString(nonce),
		Ciphertext:   base64.StdEncoding.EncodeToString(ciphertext),
	})
}

func decryptEC(privateKey *ecdsa.PrivateKey, env HybridEnvelope) ([]byte, error) {
	curve, err := ecdhCurveForAlgorithm(env.Alg)
	if err != nil {
		return nil, err
	}
	ownPrivateKey, err := privateKey.ECDH()
	if err != nil {
		return nil, fmt.Errorf("converting private key to ecdh: %w", err)
	}
	if ownPrivateKey.Curve() != curve {
		return nil, fmt.Errorf("hybrid envelope curve does not match private key")
	}
	rawEphemeralPublicKey, err := base64.StdEncoding.DecodeString(env.EphemeralPub)
	if err != nil {
		return nil, fmt.Errorf("decoding ephemeral public key: %w", err)
	}
	ephemeralPublicKey, err := curve.NewPublicKey(rawEphemeralPublicKey)
	if err != nil {
		return nil, fmt.Errorf("parsing ephemeral public key: %w", err)
	}
	sharedSecret, err := ownPrivateKey.ECDH(ephemeralPublicKey)
	if err != nil {
		return nil, fmt.Errorf("computing ecdh shared secret: %w", err)
	}
	defer clearBytes(sharedSecret)

	sessionKey, err := deriveHybridKey(sharedSecret)
	if err != nil {
		return nil, err
	}
	defer clearBytes(sessionKey)

	return decryptAESGCM(sessionKey, env.Nonce, env.Ciphertext)
}

func ecdhCurveForPublicKey(publicKey *ecdsa.PublicKey) (ecdh.Curve, string, error) {
	switch publicKey.Curve {
	case elliptic.P256():
		return ecdh.P256(), AlgECIESP256AES256GCM, nil
	case elliptic.P384():
		return ecdh.P384(), AlgECIESP384AES256GCM, nil
	case elliptic.P521():
		return ecdh.P521(), AlgECIESP521AES256GCM, nil
	default:
		return nil, "", fmt.Errorf("unsupported ec public key curve")
	}
}

func ecdhCurveForAlgorithm(alg string) (ecdh.Curve, error) {
	switch alg {
	case AlgECIESP256AES256GCM:
		return ecdh.P256(), nil
	case AlgECIESP384AES256GCM:
		return ecdh.P384(), nil
	case AlgECIESP521AES256GCM:
		return ecdh.P521(), nil
	default:
		return nil, fmt.Errorf("unsupported ec hybrid algorithm %q", alg)
	}
}

func deriveHybridKey(sharedSecret []byte) ([]byte, error) {
	key := make([]byte, aes256KeySize)
	if _, err := io.ReadFull(hkdf.New(sha256.New, sharedSecret, nil, hybridHKDFInfo), key); err != nil {
		return nil, fmt.Errorf("deriving hybrid session key: %w", err)
	}
	return key, nil
}

func encryptAESGCM(key, plaintext []byte) ([]byte, []byte, error) {
	aead, err := aesGCM(key)
	if err != nil {
		return nil, nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, fmt.Errorf("generating hybrid nonce: %w", err)
	}
	return nonce, aead.Seal(nil, nonce, plaintext, nil), nil
}

func decryptAESGCM(key []byte, encodedNonce, encodedCiphertext string) ([]byte, error) {
	nonce, err := base64.StdEncoding.DecodeString(encodedNonce)
	if err != nil {
		return nil, fmt.Errorf("decoding hybrid nonce: %w", err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(encodedCiphertext)
	if err != nil {
		return nil, fmt.Errorf("decoding hybrid ciphertext: %w", err)
	}
	aead, err := aesGCM(key)
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypting hybrid ciphertext: %w", err)
	}
	return plaintext, nil
}

func aesGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != aes256KeySize {
		return nil, fmt.Errorf("hybrid secret key must be %d bytes", aes256KeySize)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating hybrid aes cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating hybrid gcm cipher: %w", err)
	}
	return aead, nil
}

func marshalHybridEnvelope(env HybridEnvelope) ([]byte, error) {
	payload, err := json.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("marshalling hybrid secret envelope: %w", err)
	}
	return payload, nil
}

func clearBytes(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
