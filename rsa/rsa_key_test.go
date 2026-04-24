package rsa

import (
	"crypto/x509"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMarshalPKCS1PrivateKey(t *testing.T) {
	privateKey, err := GenerateKey(2048)
	require.NoError(t, err)

	marshaled, err := MarshalPKCS1PrivateKey(privateKey)
	require.NoError(t, err)

	expectedPrivateDER := x509.MarshalPKCS1PrivateKey(privateKey)
	expectedPublicDER := x509.MarshalPKCS1PublicKey(&privateKey.PublicKey)

	require.Equal(t, expectedPrivateDER, marshaled.PKCS1PrivateKeyDER)
	require.Equal(t, expectedPublicDER, marshaled.PKCS1PublicKeyDER)
	require.Contains(t, marshaled.PKCS1PrivateKeyPEM, "BEGIN RSA PRIVATE KEY")
	require.Contains(t, marshaled.PKCS1PublicKeyPEM, "BEGIN RSA PUBLIC KEY")

	parsedPrivate, err := ParsePrivateKey(marshaled.PKCS1PrivateKeyPEM)
	require.NoError(t, err)
	require.Equal(t, privateKey.N, parsedPrivate.N)

	parsedPublic, err := ParsePublicKey(marshaled.PKCS1PublicKeyPEM)
	require.NoError(t, err)
	require.Equal(t, privateKey.PublicKey.N, parsedPublic.N)
}

func TestMarshalPKCS8PrivateKey(t *testing.T) {
	privateKey, err := GenerateKey(2048)
	require.NoError(t, err)

	marshaled, err := MarshalPKCS8PrivateKey(privateKey)
	require.NoError(t, err)

	expectedPrivateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	require.NoError(t, err)
	expectedPublicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	require.NoError(t, err)

	require.Equal(t, expectedPrivateDER, marshaled.PKCS8PrivateKeyDER)
	require.Equal(t, expectedPublicDER, marshaled.PKCS8PublicKeyDER)
	require.Contains(t, marshaled.PKCS8PrivateKeyPEM, "BEGIN PRIVATE KEY")
	require.Contains(t, marshaled.PKCS8PublicKeyPEM, "BEGIN PUBLIC KEY")

	parsedPrivate, err := ParsePrivateKey(marshaled.PKCS8PrivateKeyPEM)
	require.NoError(t, err)
	require.Equal(t, privateKey.N, parsedPrivate.N)

	parsedPublic, err := ParsePublicKey(marshaled.PKCS8PublicKeyPEM)
	require.NoError(t, err)
	require.Equal(t, privateKey.PublicKey.N, parsedPublic.N)
}

func TestMarshalPEMFormatting(t *testing.T) {
	privateKey, err := GenerateKey(2048)
	require.NoError(t, err)

	pkcs1, err := MarshalPKCS1PrivateKey(privateKey)
	require.NoError(t, err)

	pkcs8, err := MarshalPKCS8PrivateKey(privateKey)
	require.NoError(t, err)

	for _, pemText := range []string{
		pkcs1.PKCS1PrivateKeyPEM,
		pkcs1.PKCS1PublicKeyPEM,
		pkcs8.PKCS8PrivateKeyPEM,
		pkcs8.PKCS8PublicKeyPEM,
	} {
		require.True(t, strings.HasPrefix(pemText, "-----BEGIN "))
		require.True(t, strings.HasSuffix(pemText, "-----\n"))
	}
}
