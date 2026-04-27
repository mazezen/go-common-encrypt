package ecdsa

import (
	"crypto/elliptic"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	// only use test
	priv_key_hex = "1d1c93970892fcfea7d593f529e35b8ab82ce12f0279a00c41ffbfbb"
	pub_key_hex  = "04bf9009308c18cc253def307edddd34406e22b8056d127a273770531448e0c97063df3e1b699fe300b934272f6612cac1ea35fad135734813"
	message      = []byte("hello, world")
)

func TestSignWithMD5ToBase64(t *testing.T) {
	priv, err := ParsePrivateKeyFromHex(elliptic.P224(), priv_key_hex)
	require.NoError(t, err, "parse private key from hex error: ", err)
	require.NotNil(t, priv, "parse private key is nill")

	pub, err := ParsePublicKeyFromHex(elliptic.P224(), pub_key_hex)
	require.NoError(t, err, "parse public key from hex error: ", err)
	require.NotNil(t, priv, "parse public key is nill")

	sig, err := SignWithMD5ToBase64(priv, message)
	require.NoError(t, err, "sign with md5 to base64 error: ", err)
	require.NotEmpty(t, sig, "sign with md5 to base64 is empty ")
	fmt.Printf("signature: %s\n", sig)

	b := VerifySignWithMD5FromBase64(&pub, message, sig)
	require.NotEqual(t, false, b, "verify signature failed")
	fmt.Printf("verify signature: %v\n", b)
}

func TestSignWithSha1ToBase64(t *testing.T) {
	priv, err := ParsePrivateKeyFromHex(elliptic.P224(), priv_key_hex)
	require.NoError(t, err, "parse private key from hex error: ", err)
	require.NotNil(t, priv, "parse private key is nill")

	pub, err := ParsePublicKeyFromHex(elliptic.P224(), pub_key_hex)
	require.NoError(t, err, "parse public key from hex error: ", err)
	require.NotNil(t, priv, "parse public key is nill")

	sig, err := SignWithSha1ToBase64(priv, message)
	require.NoError(t, err, "sign with sha1 to base64 error: ", err)
	require.NotEmpty(t, sig, "sign with sha1 to base64 is empty ")
	fmt.Printf("signature: %s\n", sig)

	b := VerifySignWithSha1FromBase64(&pub, message, sig)
	require.NotEqual(t, false, b, "verify signature failed")
	fmt.Printf("verify signature: %v\n", b)
}

func TestSignWithSha224ToBase64(t *testing.T) {
	priv, err := ParsePrivateKeyFromHex(elliptic.P224(), priv_key_hex)
	require.NoError(t, err, "parse private key from hex error: ", err)
	require.NotNil(t, priv, "parse private key is nill")

	pub, err := ParsePublicKeyFromHex(elliptic.P224(), pub_key_hex)
	require.NoError(t, err, "parse public key from hex error: ", err)
	require.NotNil(t, priv, "parse public key is nill")

	sig, err := SignWithSha224ToBase64(priv, message)
	require.NoError(t, err, "sign with sha224 to base64 error: ", err)
	require.NotEmpty(t, sig, "sign with sha224 to base64 is empty ")
	fmt.Printf("signature: %s\n", sig)

	b := VerifySignWithSha224FromBase64(&pub, message, sig)
	require.NotEqual(t, false, b, "verify signature failed")
	fmt.Printf("verify signature: %v\n", b)
}

func TestSignWithSha256ToBase64(t *testing.T) {
	priv, err := ParsePrivateKeyFromHex(elliptic.P224(), priv_key_hex)
	require.NoError(t, err, "parse private key from hex error: ", err)
	require.NotNil(t, priv, "parse private key is nill")

	pub, err := ParsePublicKeyFromHex(elliptic.P224(), pub_key_hex)
	require.NoError(t, err, "parse public key from hex error: ", err)
	require.NotNil(t, priv, "parse public key is nill")

	sig, err := SignWithSha256ToBase64(priv, message)
	require.NoError(t, err, "sign with sha256 to base64 error: ", err)
	require.NotEmpty(t, sig, "sign with sha256 to base64 is empty ")
	fmt.Printf("signature: %s\n", sig)

	b := VerifySignWithSha256FromBase64(&pub, message, sig)
	require.NotEqual(t, false, b, "verify signature failed")
	fmt.Printf("verify signature: %v\n", b)
}

func TestSignWithSha512ToBase64(t *testing.T) {
	priv, err := ParsePrivateKeyFromHex(elliptic.P224(), priv_key_hex)
	require.NoError(t, err, "parse private key from hex error: ", err)
	require.NotNil(t, priv, "parse private key is nill")

	pub, err := ParsePublicKeyFromHex(elliptic.P224(), pub_key_hex)
	require.NoError(t, err, "parse public key from hex error: ", err)
	require.NotNil(t, priv, "parse public key is nill")

	sig, err := SignWithSha512ToBase64(priv, message)
	require.NoError(t, err, "sign with sha512 to base64 error: ", err)
	require.NotEmpty(t, sig, "sign with sha512 to base64 is empty ")
	fmt.Printf("signature: %s\n", sig)

	b := VerifySignWithSha512FromBase64(&pub, message, sig)
	require.NotEqual(t, false, b, "verify signature failed")
	fmt.Printf("verify signature: %v\n", b)
}
