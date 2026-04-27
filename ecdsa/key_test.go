package ecdsa

import (
	"crypto/elliptic"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGenerateKey(t *testing.T) {
	// elliptic.P224()
	// generate private key
	priv224, err := GenerateKeyWithEllipticP224()
	require.NoError(t, err, "GenerateKeyWithEllipticP224 error: ", err)
	require.NotNil(t, priv224, "priv224 is nill")

	// export public key from private key
	pub224 := ExportPublic(priv224)
	require.NotNil(t, pub224, "pub224 is nill")

	// convert private key to bytes
	privB, err := PrivateKeyToBytes(priv224)
	require.NoError(t, err, "private convert to byte error: ", err)
	require.NotNil(t, privB, "private convert to byte is nill")

	// convert private key to hex string
	privHex := PrivateKeyToHex(priv224)
	fmt.Printf("priv224 hex is  -> : %s\n", privHex)

	// convert public key to bytes
	pubB, err := PublicKeyToBytes(pub224)
	require.NoError(t, err, "public key convert to byte error: ", err)
	require.NotNil(t, pubB, "public key convert to byte is nill")

	// convert public key to hex string
	pubHex := PublicKeyToHex(pub224)
	fmt.Printf("pub224 hex is  -> : %s\n", pubHex)

	// get *ecdsa.PrivateKey from private key bytes
	priv224P, err := ParsePrivateKeyFromBytes(elliptic.P224(), privB)
	require.NoError(t, err, "parse private key from bytes error: ", err)
	require.NotNil(t, priv224P, "parse private key from bytes is nill")
	require.Equal(t, priv224, priv224P, "parse private key from bytes failed")

	// get *ecdsa.PrivateKey from private key hex
	priv224PH, err := ParsePrivateKeyFromHex(elliptic.P224(), privHex)
	require.NoError(t, err, "parse private key from hex error: ", err)
	require.NotNil(t, priv224PH, "parse private key from hex is nill")
	require.Equal(t, priv224, priv224PH, "parse private key from hex failed")

	// get *ecdsa.Publickey from public key bytes
	pub224P, err := ParsePublicKeyFromBytes(elliptic.P224(), pubB)
	require.NoError(t, err, "parse public key from bytes error: ", err)
	require.NotNil(t, pub224P, "parse public key from bytes is nill")
	require.Equal(t, pub224, pub224P, "parse private key from bytes failed")

	// get *ecdsa.Publickey from public key hex
	pub224H, err := ParsePublicKeyFromHex(elliptic.P224(), pubHex)
	require.NoError(t, err, "parse public key from hex error: ", err)
	require.NotNil(t, pub224H, "parse public key from bytes is nill")
	require.Equal(t, pub224, pub224H, "parse private key from bytes failed")
}
