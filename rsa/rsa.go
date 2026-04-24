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
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// RSAEncryptOAEP encrypts plaintext with RSA-OAEP.
func RSAEncryptOAEP(pub *rsa.PublicKey, plaintext []byte) ([]byte, error) {
	return EncryptOAEP(pub, plaintext)
}

// RSADecryptOAEP decrypts RSA-OAEP ciphertext.
func RSADecryptOAEP(priv *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
	return DecryptOAEP(priv, ciphertext)
}

// RSAEncryptOAEPWithBase64 encrypts plaintext with RSA-OAEP and returns base64 ciphertext.
func RSAEncryptOAEPWithBase64(pub *rsa.PublicKey, plaintext []byte) (string, error) {
	cb, err := RSAEncryptOAEP(pub, plaintext)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(cb), nil
}

// RSADecryptOAEPWithBase64 decrypts base64-encoded RSA-OAEP ciphertext.
func RSADecryptOAEPWithBase64(priv *rsa.PrivateKey, ciphertext string) (string, error) {
	cb, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrInvalidBase64Ciphertext, err)
	}
	b, err := RSADecryptOAEP(priv, cb)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// RSAEncryptPKCS encrypts plaintext with RSA PKCS#1 v1.5.
//
// Deprecated: PKCS#1 v1.5 encryption should only be used for legacy
// compatibility. Prefer RSAEncryptOAEP for new code.
func RSAEncryptPKCS(pub *rsa.PublicKey, plaintext []byte) ([]byte, error) {
	return EncryptPKCS1v15(pub, plaintext)
}

// RSADecryptPKCS decrypts RSA PKCS#1 v1.5 ciphertext.
//
// Deprecated: PKCS#1 v1.5 decryption should only be used for legacy
// compatibility. Prefer RSADecryptOAEP for new code.
func RSADecryptPKCS(priv *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
	return DecryptPKCS1v15(priv, ciphertext)
}

// RSAEncryptPKCSWithBase64 encrypts plaintext with RSA PKCS#1 v1.5
// and returns base64 encoded ciphertext.
//
// Deprecated: PKCS#1 v1.5 encryption should only be used for legacy
// compatibility. Prefer RSAEncryptOAEPWithBase64 for new code.
func RSAEncryptPKCSWithBase64(pub *rsa.PublicKey, plaintext []byte) (string, error) {
	b, err := RSAEncryptPKCS(pub, plaintext)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// RSADecryptPKCSWithBase64 decrypts base64 encoded RSA PKCS#1 v1.5 ciphertext.
//
// Deprecated: PKCS#1 v1.5 decryption should only be used for legacy
// compatibility. Prefer RSADecryptOAEPWithBase64 for new code.
func RSADecryptPKCSWithBase64(priv *rsa.PrivateKey, ciphertext string) (string, error) {
	bp, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrInvalidBase64Ciphertext, err)
	}

	b, err := RSADecryptPKCS(priv, bp)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// SignPKCS1v15 signs a message with RSA PKCS#1 v1.5 using SHA-256.
//
// Deprecated: prefer SignPSS for new code.
func SignPKCS1v15(priv *rsa.PrivateKey, message []byte) ([]byte, error) {
	hashed := sha256.Sum256(message)
	return rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hashed[:])
}

// SignPKCS signs a message with RSA PKCS#1 v1.5 using SHA-256.
//
// Deprecated: use SignPKCS1v15.
func SignPKCS(priv *rsa.PrivateKey, message []byte) ([]byte, error) {
	return SignPKCS1v15(priv, message)
}

// VerifyPKCS1v15 verifies an RSA PKCS#1 v1.5 signature using SHA-256.
//
// Deprecated: prefer VerifyPSS for new code.
func VerifyPKCS1v15(pub *rsa.PublicKey, sig []byte, message []byte) (bool, error) {
	hashed := sha256.Sum256(message)
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, hashed[:], sig); err != nil {
		return false, err
	}
	return true, nil
}

// SignPSS signs a message with RSA-PSS using SHA-256.
func SignPSS(priv *rsa.PrivateKey, message []byte) ([]byte, error) {
	digest := sha256.Sum256(message)
	options := &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA256,
	}
	return rsa.SignPSS(rand.Reader, priv, crypto.SHA256, digest[:], options)
}

// VerifyPSS verifies an RSA-PSS signature using SHA-256.
func VerifyPSS(pub *rsa.PublicKey, signature []byte, message []byte) error {
	digest := sha256.Sum256(message)
	options := &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA256,
	}
	return rsa.VerifyPSS(pub, crypto.SHA256, digest[:], signature, options)
}
