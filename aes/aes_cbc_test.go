package aes

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewAesCBC(t *testing.T) {
	type args struct {
		k  []byte
		n  uint
		fm string
	}
	tests := []struct {
		name      string
		args      args
		plainText string
	}{
		{
			name: "Test AES-CBC-PKCS7 AES-128",
			args: args{
				k: []byte("1ockKIb8Kg6s4uc8"),
				n: 16,
				// fm: "PKCS#7",
			},
			plainText: `hello\x00\x00`,
		},
		{
			name: "Test AES-CBC-PKCS7 AES-192",
			args: args{
				k:  []byte("1ockKIb8Kg6s4uc8opkljuhh"),
				n:  16,
				fm: "PKCS#7",
			},
			plainText: `hello\x00\x00`,
		},
		{
			name: "Test AES-CBC-PKCS7 AES-256",
			args: args{
				k:  []byte("1ockKIb8Kg6s4uc8opkljuhhklkj78hu"),
				n:  16,
				fm: "PKCS#7",
			},
			plainText: `hello\x00\x00`,
		},
		// -----------------------------------------------------------------
		{
			name: "Test AES-CBC-ZeroPadding AES-128",
			args: args{
				k:  []byte("1ockKIb8Kg6s4uc8"),
				n:  16,
				fm: "ZeroPadding",
			},
			plainText: `hello\x00\x00`,
		},
		{
			name: "Test AES-CBC-ZeroPadding AES-128",
			args: args{
				k:  []byte("1ockKIb8Kg6s4uc8opkljuhh"),
				n:  16,
				fm: "ZeroPadding",
			},
			plainText: `hello\x00\x00`,
		},
		{
			name: "Test AES-CBC-ZeroPadding AES-128",
			args: args{
				k:  []byte("1ockKIb8Kg6s4uc8opkljuhhklkj78hu"),
				n:  16,
				fm: "ZeroPadding",
			},
			plainText: `hello\x00\x00`,
		},

		// -----------------------------------------------------------------
		{
			name: "Test AES-CBC-NoPadding AES-128",
			args: args{
				k:  []byte("1ockKIb8Kg6s4uc8"),
				n:  16,
				fm: "NoPadding",
			},
			plainText: `hellohellohehehe`,
		},
		{
			name: "Test AES-CBC-NoPadding AES-128",
			args: args{
				k:  []byte("1ockKIb8Kg6s4uc8opkljuhh"),
				n:  16,
				fm: "NoPadding",
			},
			plainText: `hellohellohehehe99001122`,
		},
		{
			name: "Test AES-CBC-NoPadding AES-128",
			args: args{
				k:  []byte("1ockKIb8Kg6s4uc8opkljuhhklkj78hu"),
				n:  16,
				fm: "NoPadding",
			},
			plainText: `hellohellohehehe9900112234uhyu`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if len(tt.plainText)%16 != 0 && tt.args.fm == "NoPadding" {
				t.Logf("Skipping NoPadding test: plaintext length is not a multiple of 16")
				return
			}
			aesCBC := NewAesCBC(tt.args.k, tt.args.n, tt.args.fm)
			cipherText, err := aesCBC.AesCBCCipher([]byte(tt.plainText))
			assert.NoError(t, err, "aes-cbc-pkcs7 aes-128 encrypt failed")
			assert.NotEmpty(t, cipherText, "cipherText should not be empty")

			// fmt.Println(cipherText)
			// fmt.Println("==================================================================")

			decipherPlainText, err := aesCBC.AesCBDDecipher(cipherText)
			assert.NoError(t, err, "aes-cbc-pkcs7 aes-128 decrypt failed")
			assert.Equal(t, tt.plainText, decipherPlainText, "decrypted text should match original")

			// fmt.Println(decipherPlainText)
		})
	}
}
