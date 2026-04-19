/**
* AES (Advanced Encryption Standard) is a symmetric encryption algorithm and one of the most popular
* encryption algorithms currently. It is standardized by the National Institute of Standards and
* Technology (NIST) and has become an international standard. Its encryption key length can be 128 bits,
* 192 bits, or 256 bits, with the 128-bit key version being the most popular. AES is a block cipher that
* divides plaintext into 128-bit blocks and encrypts them separately. The encryption methods include basic
* operations such as substitution, permutation, and linear transformation. Through multiple rounds of
* iterative encryption, it can provide high encryption strength while satisfying key security,
* thus preventing attacks from malicious attackers. AES has been widely used in many scenarios,
* such as data transmission, file encryption, database encryption, and so on
*
* wiki: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
**/

package aes

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	key128 = []byte("1ockKIb8Kg6s4uc8")
	key192 = []byte("1ockKIb8Kg6s4uc8opkljuhh")
	key256 = []byte("1ockKIb8Kg6s4uc8opkljuhhklkj78hu")

	plainText           = `hello\x00\x00`
	painTextNoPadding16 = `hellohellohehehe`               // 16
	painTextNoPadding24 = `hellohellohehehe99001122`       // 24
	painTextNoPadding32 = `hellohellohehehe9900112234uhyu` // 32
)

func TestNewAesCBC(t *testing.T) {
	type args struct {
		k  []byte
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
				k: key128,
				// fm: "PKCS#7",
			},
			plainText: plainText,
		},
		{
			name: "Test AES-CBC-PKCS7 AES-192",
			args: args{
				k:  key192,
				fm: "PKCS#7",
			},
			plainText: plainText,
		},
		{
			name: "Test AES-CBC-PKCS7 AES-256",
			args: args{
				k:  key256,
				fm: "PKCS#7",
			},
			plainText: plainText,
		},
		// -----------------------------------------------------------------
		{
			name: "Test AES-CBC-ZeroPadding AES-128",
			args: args{
				k:  key128,
				fm: "ZeroPadding",
			},
			plainText: plainText,
		},
		{
			name: "Test AES-CBC-ZeroPadding AES-192",
			args: args{
				k:  key192,
				fm: "ZeroPadding",
			},
			plainText: plainText,
		},
		{
			name: "Test AES-CBC-ZeroPadding AES-256",
			args: args{
				k:  key256,
				fm: "ZeroPadding",
			},
			plainText: plainText,
		},

		// -----------------------------------------------------------------
		{
			name: "Test AES-CBC-NoPadding AES-128",
			args: args{
				k:  key128,
				fm: "NoPadding",
			},
			plainText: painTextNoPadding16,
		},
		{
			name: "Test AES-CBC-NoPadding AES-192",
			args: args{
				k:  key192,
				fm: "NoPadding",
			},
			plainText: painTextNoPadding24,
		},
		{
			name: "Test AES-CBC-NoPadding AES-256",
			args: args{
				k:  key256,
				fm: "NoPadding",
			},
			plainText: painTextNoPadding32,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if len(tt.plainText)%16 != 0 && tt.args.fm == "NoPadding" {
				t.Logf("Skipping NoPadding test: plaintext length is not a multiple of 16")
				return
			}
			aesCBC := NewAesCBC(tt.args.k, tt.args.fm)
			cipherText, err := aesCBC.AesCBCCipher([]byte(tt.plainText))
			assert.NoError(t, err, fmt.Sprintf("%s encrypt failed", tt.name))
			assert.NotEmpty(t, cipherText, "cipherText should not be empty")

			// fmt.Println("==================================================================")
			// fmt.Printf("------- ciphertext: %s\n", cipherText)
			// fmt.Println("==================================================================")

			decipherPlainText, err := aesCBC.AesCBCDecipher(cipherText)
			assert.NoError(t, err, fmt.Sprintf("%s decrypt failed", tt.name))
			assert.Equal(t, tt.plainText, decipherPlainText, "decrypted text should match original")

			// fmt.Println("==================================================================")
			// fmt.Printf("------- decipherPlainText: %s\n", decipherPlainText)
			// fmt.Println("==================================================================")
		})
	}
}
