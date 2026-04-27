package ecdsa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
)

// GenerateKeyWithEllipticP224 generate [*ecdsa.PrivateKey] default use elliptic.P224()
func GenerateKeyWithEllipticP224() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
}

// GenerateKeyWithEllipticP256 generate [*ecdsa.PrivateKey] default use elliptic.P256()
func GenerateKeyWithEllipticP256() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// GenerateKeyWithEllipticP384 generate [*ecdsa.PrivateKey] default use elliptic.P384()
func GenerateKeyWithEllipticP384() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
}

// GenerateKeyWithEllipticP512 generate [*ecdsa.PrivateKey] default use elliptic.P521()
func GenerateKeyWithEllipticP512() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
}

// ExportPublic export [ecdsa.PublicKey] from [*ecdsa.PrivateKey]
func ExportPublic(priv *ecdsa.PrivateKey) ecdsa.PublicKey {
	return priv.PublicKey
}

// PrivateKeyToBytes convert priv which given [*ecdsa.PrivateKey] to byte type.
func PrivateKeyToBytes(priv *ecdsa.PrivateKey) ([]byte, error) {
	return priv.Bytes()
}

// PrivateKeyToHex convert priv which given [*ecdsa.PrivateKey] to hex string.
func PrivateKeyToHex(priv *ecdsa.PrivateKey) string {
	privB, err := PrivateKeyToBytes(priv)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(privB)
}

// ParsePrivateKeyFromBytes parse to [*ecdsa.PrivateKey] which given cure and data (use [PrivateKeyToBytes]).
func ParsePrivateKeyFromBytes(curve elliptic.Curve, data []byte) (*ecdsa.PrivateKey, error) {
	return ecdsa.ParseRawPrivateKey(curve, data)
}

// ParsePrivateKeyFromHex parse to [*ecdsa.PrivateKey] which given cure and data (use [PrivateKeyToHex]).
func ParsePrivateKeyFromHex(curve elliptic.Curve, data string) (*ecdsa.PrivateKey, error) {
	b, err := hex.DecodeString(data)
	if err != nil {
		return nil, err
	}

	return ParsePrivateKeyFromBytes(curve, b)
}

// PublicKeyToBytes convert pub which given [ecdsa.PublicKey] to byte type.
func PublicKeyToBytes(pub ecdsa.PublicKey) ([]byte, error) {
	return pub.Bytes()
}

// PublicKeyToHex convert pub which given [ecdsa.PublicKey] to hex string.
func PublicKeyToHex(pub ecdsa.PublicKey) string {
	pubB, err := PublicKeyToBytes(pub)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(pubB)
}

// ParsePublicKeyFromBytes parse to [ecdsa.PublicKey] which given cure and data (use [PublicKeyToBytes]).
func ParsePublicKeyFromBytes(curve elliptic.Curve, data []byte) (ecdsa.PublicKey, error) {
	pub, err := ecdsa.ParseUncompressedPublicKey(curve, data)
	if err != nil {
		return ecdsa.PublicKey{}, err
	}
	return *pub, nil
}

// ParsePublicKeyFromHex parse to [ecdsa.PublicKey] which given cure and data (use [PublicKeyToHex]).
func ParsePublicKeyFromHex(curve elliptic.Curve, data string) (ecdsa.PublicKey, error) {
	b, err := hex.DecodeString(data)
	if err != nil {
		return ecdsa.PublicKey{}, err
	}

	return ParsePublicKeyFromBytes(curve, b)
}
