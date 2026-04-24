// This is a lightweight Go RSA toolkit that encapsulates common operations such as key generation,
// PEM parsing, encryption and decryption, as well as signature verification and signing.
// It is based on the Go standard library's crypto/rsa.
// By default, it recommends using the more secure RSA-OAEP for encryption and decryption, and RSA-PSS for signing.
// The package supports both:
//  - RSA private key generation
//	- DER/PEM encoding and decoding for PKCS#1, PKCS#8, and PKIX
//	- PEM parsing of public and private keys
//	- OAEP and PKCS#1 v1.5 encryption and decryption
//	- PSS and PKCS#1 v1.5 signature verification
// The PKCS#1 v1.5 related interfaces are primarily used for compatibility with legacy systems,
// and new code should prioritize the use of OAEP and PSS

package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// EncryptOAEP encrypts plaintext with RSA-OAEP using SHA-256.
func EncryptOAEP(pub *rsa.PublicKey, plaintext []byte) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, plaintext, nil)
}

// DecryptOAEP decrypts RSA-OAEP ciphertext using SHA-256.
func DecryptOAEP(priv *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, ciphertext, nil)
}

// Deprecated: PKCS#1 v1.5 encryption should only be used for legacy compatibility.
func EncryptPKCS1v15(pub *rsa.PublicKey, plaintext []byte) ([]byte, error) {
	return rsa.EncryptPKCS1v15(rand.Reader, pub, plaintext)
}

// Deprecated: PKCS#1 v1.5 decryption should only be used for legacy compatibility.
func DecryptPKCS1v15(priv *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
	return rsa.DecryptPKCS1v15(rand.Reader, priv, ciphertext)
}

// ParsePublicKey parses an RSA public key from a PKCS#1 or PKIX PEM block.
func ParsePublicKey(pubPem string) (*rsa.PublicKey, error) {
	if pubPem == "" {
		return nil, ErrPublicKeyEmpty
	}

	block, _ := pem.Decode([]byte(pubPem))
	if block == nil {
		return nil, ErrPublicKeyInvalidPEM
	}
	switch block.Type {
	case tPKCS1PublicKeyType:
		return x509.ParsePKCS1PublicKey(block.Bytes)
	case tPKCS8PublicKeyType:
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKIX public key: %w", err)
		}
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return nil, ErrNotRSAPublicKey
		}
		return rsaPub, nil
	default:
		return nil, fmt.Errorf("%w: %s", ErrPublicKeyTypeUnsupported, block.Type)
	}
}

// ParsePrivateKey parses an RSA private key from a PKCS#1 or PKCS#8 PEM block.
func ParsePrivateKey(priPem string) (*rsa.PrivateKey, error) {
	if priPem == "" {
		return nil, ErrPrivateKeyEmpty
	}

	block, _ := pem.Decode([]byte(priPem))
	if block == nil {
		return nil, ErrPrivateKeyInvalidPEM
	}
	switch block.Type {
	case tPKCS1PrivateKeyType:
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case tPKCS8PrivateKeyType:
		priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKCS8 private key: %w", err)
		}
		rsaPriv, ok := priv.(*rsa.PrivateKey)
		if !ok {
			return nil, ErrNotRSAPrivateKey
		}
		return rsaPriv, nil
	default:
		return nil, fmt.Errorf("%w: %s", ErrPrivateKeyTypeUnsupported, block.Type)
	}
}
