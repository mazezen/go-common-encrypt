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
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

const (
	tPKCS1PrivateKeyType string = "RSA PRIVATE KEY"
	tPKCS1PublicKeyType  string = "RSA PUBLIC KEY"
	tPKCS8PrivateKeyType string = "PRIVATE KEY"
	tPKCS8PublicKeyType  string = "PUBLIC KEY"
)

type RSAKey struct {
	// PKCS#1
	PKCS1PrivateKeyDER []byte
	PKCS1PublicKeyDER  []byte
	PKCS1PrivateKeyPEM string
	PKCS1PublicKeyPEM  string

	// PKCS#8 / PKIX
	PKCS8PrivateKeyDER []byte
	PKCS8PublicKeyDER  []byte
	PKCS8PrivateKeyPEM string
	PKCS8PublicKeyPEM  string
}

// GenerateKey generates a random RSA private key of the given bit size.
// Example sizes: 1024, 2048, 3072, 4096, 8192, 16384.
//
// If bits is less than 1024, [GenerateKey] returns an error. See the "[Minimum
// key size]" section for further details.
//
// Since Go 1.26, a secure source of random bytes is always used, and the Reader is
// ignored unless GODEBUG=cryptocustomrand=1 is set. This setting will be removed
// in a future Go release. Instead, use [testing/cryptotest.SetGlobalRandom].
//
// [Minimum key size]: https://pkg.go.dev/crypto/rsa#hdr-Minimum_key_size
func GenerateKey(bits int) (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("rsa generate key: %w", err)
	}

	return privateKey, nil
}

// MarshalPKCS1PrivateKey returns PKCS#1/PEM encodings for an RSA private key.
// Deprecated: prefer [MarshalPKCS8PrivateKey] for new code.
func MarshalPKCS1PrivateKey(pk *rsa.PrivateKey) (*RSAKey, error) {
	if err := pk.Validate(); err != nil {
		return nil, fmt.Errorf("validate private key: %w", err)
	}
	publicKey := pk.PublicKey

	privateKeyDer := x509.MarshalPKCS1PrivateKey(pk)
	publicKeyDer := x509.MarshalPKCS1PublicKey(&publicKey)

	return &RSAKey{
		PKCS1PrivateKeyDER: privateKeyDer,
		PKCS1PublicKeyDER:  publicKeyDer,
		PKCS1PrivateKeyPEM: string(pem.EncodeToMemory(&pem.Block{
			Type:  tPKCS1PrivateKeyType,
			Bytes: privateKeyDer,
		})),
		PKCS1PublicKeyPEM: string(pem.EncodeToMemory(&pem.Block{
			Type:  tPKCS1PublicKeyType,
			Bytes: publicKeyDer,
		})),
	}, nil
}

// MarshalPKCS8PrivateKey returns PKCS#8/PKIX PEM encodings for an RSA private key.
func MarshalPKCS8PrivateKey(pk *rsa.PrivateKey) (*RSAKey, error) {
	publicKey := pk.PublicKey

	privateKeyDer, err := x509.MarshalPKCS8PrivateKey(pk)
	if err != nil {
		return nil, err
	}
	publicKeyDer, err := x509.MarshalPKIXPublicKey(&publicKey)
	if err != nil {
		return nil, err
	}

	return &RSAKey{
		PKCS8PrivateKeyDER: privateKeyDer,
		PKCS8PublicKeyDER:  publicKeyDer,
		PKCS8PrivateKeyPEM: string(pem.EncodeToMemory(&pem.Block{
			Type:  tPKCS8PrivateKeyType,
			Bytes: privateKeyDer,
		})),
		PKCS8PublicKeyPEM: string(pem.EncodeToMemory(&pem.Block{
			Type:  tPKCS8PublicKeyType,
			Bytes: publicKeyDer,
		})),
	}, nil
}
