package rsa

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

const plaintextWords = `EncryptPKCS1v15 encrypts the given message with RSA and the padding scheme from PKCS #1 v1.5. The message must be no longer than the length of the public modulus minus 11 bytes.`

type testKeyMaterial struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	pkcs1      *RSAKey
	pkcs8      *RSAKey
}

func mustTestKeyMaterial(t *testing.T) testKeyMaterial {
	t.Helper()

	privateKey, err := GenerateKey(2048)
	require.NoError(t, err)

	pkcs1, err := MarshalPKCS1PrivateKey(privateKey)
	require.NoError(t, err)

	pkcs8, err := MarshalPKCS8PrivateKey(privateKey)
	require.NoError(t, err)

	return testKeyMaterial{
		privateKey: privateKey,
		publicKey:  &privateKey.PublicKey,
		pkcs1:      pkcs1,
		pkcs8:      pkcs8,
	}
}

func TestGenerateKey(t *testing.T) {
	t.Run("valid size", func(t *testing.T) {
		key, err := GenerateKey(2048)
		require.NoError(t, err)
		require.NotNil(t, key)
		require.Equal(t, 2048, key.N.BitLen())
		require.NoError(t, key.Validate())
	})

	t.Run("rejects too-small size", func(t *testing.T) {
		key, err := GenerateKey(512)
		require.Error(t, err)
		require.Nil(t, key)
	})
}

func TestParsePublicKey(t *testing.T) {
	material := mustTestKeyMaterial(t)

	tests := []struct {
		name string
		pem  string
	}{
		{name: "pkcs1", pem: material.pkcs1.PKCS1PublicKeyPEM},
		{name: "pkix", pem: material.pkcs8.PKCS8PublicKeyPEM},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pub, err := ParsePublicKey(tc.pem)
			require.NoError(t, err)
			require.Equal(t, material.publicKey.N, pub.N)
			require.Equal(t, material.publicKey.E, pub.E)
		})
	}
}

func TestParsePrivateKey(t *testing.T) {
	material := mustTestKeyMaterial(t)

	tests := []struct {
		name string
		pem  string
	}{
		{name: "pkcs1", pem: material.pkcs1.PKCS1PrivateKeyPEM},
		{name: "pkcs8", pem: material.pkcs8.PKCS8PrivateKeyPEM},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			priv, err := ParsePrivateKey(tc.pem)
			require.NoError(t, err)
			require.Equal(t, material.privateKey.N, priv.N)
			require.Equal(t, material.privateKey.E, priv.E)
			require.NoError(t, priv.Validate())
		})
	}
}

func TestParseKeyErrors(t *testing.T) {
	t.Run("empty public key", func(t *testing.T) {
		key, err := ParsePublicKey("")
		require.Nil(t, key)
		require.ErrorIs(t, err, ErrPublicKeyEmpty)
	})

	t.Run("empty private key", func(t *testing.T) {
		key, err := ParsePrivateKey("")
		require.Nil(t, key)
		require.ErrorIs(t, err, ErrPrivateKeyEmpty)
	})

	t.Run("invalid public key pem", func(t *testing.T) {
		key, err := ParsePublicKey("not pem")
		require.Nil(t, key)
		require.ErrorIs(t, err, ErrPublicKeyInvalidPEM)
	})

	t.Run("invalid private key pem", func(t *testing.T) {
		key, err := ParsePrivateKey("not pem")
		require.Nil(t, key)
		require.ErrorIs(t, err, ErrPrivateKeyInvalidPEM)
	})

	t.Run("unsupported public key type", func(t *testing.T) {
		pemText := string(pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: []byte("not-a-key"),
		}))

		key, err := ParsePublicKey(pemText)
		require.Nil(t, key)
		require.ErrorIs(t, err, ErrPublicKeyTypeUnsupported)
	})

	t.Run("unsupported private key type", func(t *testing.T) {
		pemText := string(pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: []byte("not-a-key"),
		}))

		key, err := ParsePrivateKey(pemText)
		require.Nil(t, key)
		require.ErrorIs(t, err, ErrPrivateKeyTypeUnsupported)
	})

	t.Run("pkix public key that is not rsa", func(t *testing.T) {
		publicKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		publicKeyDER, err := x509.MarshalPKIXPublicKey(publicKey)
		require.NoError(t, err)

		pemText := string(pem.EncodeToMemory(&pem.Block{
			Type:  tPKCS8PublicKeyType,
			Bytes: publicKeyDER,
		}))

		key, err := ParsePublicKey(pemText)
		require.Nil(t, key)
		require.ErrorIs(t, err, ErrNotRSAPublicKey)
	})

	t.Run("pkcs8 private key that is not rsa", func(t *testing.T) {
		_, privateKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
		require.NoError(t, err)

		pemText := string(pem.EncodeToMemory(&pem.Block{
			Type:  tPKCS8PrivateKeyType,
			Bytes: privateKeyDER,
		}))

		key, err := ParsePrivateKey(pemText)
		require.Nil(t, key)
		require.ErrorIs(t, err, ErrNotRSAPrivateKey)
	})
}

func TestEncryptDecrypt(t *testing.T) {
	material := mustTestKeyMaterial(t)
	message := []byte(plaintextWords)

	tests := []struct {
		name    string
		encrypt func(*testing.T) []byte
		decrypt func(*testing.T, []byte) []byte
	}{
		{
			name: "oaep helper",
			encrypt: func(t *testing.T) []byte {
				t.Helper()
				ciphertext, err := EncryptOAEP(material.publicKey, message)
				require.NoError(t, err)
				return ciphertext
			},
			decrypt: func(t *testing.T, ciphertext []byte) []byte {
				t.Helper()
				plaintext, err := DecryptOAEP(material.privateKey, ciphertext)
				require.NoError(t, err)
				return plaintext
			},
		},
		{
			name: "oaep wrapper",
			encrypt: func(t *testing.T) []byte {
				t.Helper()
				ciphertext, err := RSAEncryptOAEP(material.publicKey, message)
				require.NoError(t, err)
				return ciphertext
			},
			decrypt: func(t *testing.T, ciphertext []byte) []byte {
				t.Helper()
				plaintext, err := RSADecryptOAEP(material.privateKey, ciphertext)
				require.NoError(t, err)
				return plaintext
			},
		},
		{
			name: "pkcs1v15 helper",
			encrypt: func(t *testing.T) []byte {
				t.Helper()
				ciphertext, err := EncryptPKCS1v15(material.publicKey, message)
				require.NoError(t, err)
				return ciphertext
			},
			decrypt: func(t *testing.T, ciphertext []byte) []byte {
				t.Helper()
				plaintext, err := DecryptPKCS1v15(material.privateKey, ciphertext)
				require.NoError(t, err)
				return plaintext
			},
		},
		{
			name: "pkcs1v15 wrapper",
			encrypt: func(t *testing.T) []byte {
				t.Helper()
				ciphertext, err := RSAEncryptPKCS(material.publicKey, message)
				require.NoError(t, err)
				return ciphertext
			},
			decrypt: func(t *testing.T, ciphertext []byte) []byte {
				t.Helper()
				plaintext, err := RSADecryptPKCS(material.privateKey, ciphertext)
				require.NoError(t, err)
				return plaintext
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ciphertext := tc.encrypt(t)
			require.NotEmpty(t, ciphertext)
			require.NotEqual(t, message, ciphertext)

			plaintext := tc.decrypt(t, ciphertext)
			require.Equal(t, message, plaintext)
		})
	}
}

func TestBase64EncryptDecrypt(t *testing.T) {
	material := mustTestKeyMaterial(t)
	message := []byte(plaintextWords)

	t.Run("oaep", func(t *testing.T) {
		ciphertext, err := RSAEncryptOAEPWithBase64(material.publicKey, message)
		require.NoError(t, err)
		require.NotEmpty(t, ciphertext)

		plaintext, err := RSADecryptOAEPWithBase64(material.privateKey, ciphertext)
		require.NoError(t, err)
		require.Equal(t, plaintextWords, plaintext)
	})

	t.Run("pkcs1v15", func(t *testing.T) {
		ciphertext, err := RSAEncryptPKCSWithBase64(material.publicKey, message)
		require.NoError(t, err)
		require.NotEmpty(t, ciphertext)

		plaintext, err := RSADecryptPKCSWithBase64(material.privateKey, ciphertext)
		require.NoError(t, err)
		require.Equal(t, plaintextWords, plaintext)
	})
}

func TestBase64DecryptErrors(t *testing.T) {
	material := mustTestKeyMaterial(t)

	t.Run("oaep invalid base64", func(t *testing.T) {
		plaintext, err := RSADecryptOAEPWithBase64(material.privateKey, "%%%")
		require.Empty(t, plaintext)
		require.ErrorIs(t, err, ErrInvalidBase64Ciphertext)
	})

	t.Run("pkcs1v15 invalid base64", func(t *testing.T) {
		plaintext, err := RSADecryptPKCSWithBase64(material.privateKey, "%%%")
		require.Empty(t, plaintext)
		require.ErrorIs(t, err, ErrInvalidBase64Ciphertext)
	})
}

func TestSignVerify(t *testing.T) {
	material := mustTestKeyMaterial(t)
	message := []byte("message to be signed")

	t.Run("pkcs1v15", func(t *testing.T) {
		signature, err := SignPKCS1v15(material.privateKey, message)
		require.NoError(t, err)
		require.NotEmpty(t, signature)

		verified, err := VerifyPKCS1v15(material.publicKey, signature, message)
		require.NoError(t, err)
		require.True(t, verified)

		verified, err = VerifyPKCS1v15(material.publicKey, signature, []byte("tampered"))
		require.Error(t, err)
		require.False(t, verified)
	})

	t.Run("pss", func(t *testing.T) {
		signature, err := SignPSS(material.privateKey, message)
		require.NoError(t, err)
		require.NotEmpty(t, signature)

		err = VerifyPSS(material.publicKey, signature, message)
		require.NoError(t, err)

		err = VerifyPSS(material.publicKey, signature, []byte("tampered"))
		require.Error(t, err)
	})
}

func TestDecryptWithWrongKeyFails(t *testing.T) {
	first := mustTestKeyMaterial(t)
	second := mustTestKeyMaterial(t)

	ciphertext, err := EncryptOAEP(first.publicKey, []byte("secret"))
	require.NoError(t, err)

	plaintext, err := DecryptOAEP(second.privateKey, ciphertext)
	require.Nil(t, plaintext)
	require.Error(t, err)
}

func TestSentinelErrorsRemainDiscoverable(t *testing.T) {
	material := mustTestKeyMaterial(t)

	_, err := RSADecryptOAEPWithBase64(material.privateKey, "%%%")
	require.True(t, errors.Is(err, ErrInvalidBase64Ciphertext))
}
