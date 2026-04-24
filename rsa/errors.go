package rsa

import "errors"

var (
	ErrPublicKeyEmpty       = errors.New("public key cannot be empty")
	ErrPublicKeyInvalidPEM  = errors.New("failed to parse PEM block containing public key")
	ErrPrivateKeyEmpty      = errors.New("private key cannot be empty")
	ErrPrivateKeyInvalidPEM = errors.New("failed to parse PEM block containing private key")

	ErrPublicKeyTypeUnsupported  = errors.New("unsupported RSA public key type")
	ErrPrivateKeyTypeUnsupported = errors.New("unsupported RSA private key type")
	ErrNotRSAPublicKey           = errors.New("not an RSA public key")
	ErrNotRSAPrivateKey          = errors.New("not an RSA private key")
	ErrInvalidBase64Ciphertext   = errors.New("invalid base64 ciphertext")
	ErrInvalidHexSignature       = errors.New("invalid hex signature")
)
