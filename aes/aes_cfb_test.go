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

func TestNewAesCFB(t *testing.T) {
	type args struct {
		key []byte
		fm  string
	}
	tests := []struct {
		name      string
		args      args
		plainText string
	}{
		// -----------------------------------------------------------------
		// AES-CFB-128 PKCS#7
		{
			name: "AES-CFB-128-PKCS#7",
			args: args{
				key: key128,
				fm:  "PKCS#7",
			},
			plainText: plainOFBText,
		},
		// AES-CFB-192 PKCS#7
		{
			name: "AES-CFB-192-PKCS#7",
			args: args{
				key: key192,
				fm:  "PKCS#7",
			},
			plainText: plainOFBText,
		},
		// AES-CFB-256 PKCS#7
		{
			name: "AES-CFB-256-PKCS#7",
			args: args{
				key: key256,
				fm:  "PKCS#7",
			},
			plainText: plainOFBText,
		},

		// -----------------------------------------------------------------
		// AES-CFB-128 ZeroPadding
		{
			name: "AES-CFB-128-ZeroPadding",
			args: args{
				key: key128,
				fm:  "ZeroPadding",
			},
			plainText: plainOFBText,
		},
		// AES-CFB-192 ZeroPadding
		{
			name: "AES-CFB-192-ZeroPadding",
			args: args{
				key: key192,
				fm:  "ZeroPadding",
			},
			plainText: plainOFBText,
		},
		// AES-CFB-256 ZeroPadding
		{
			name: "AES-CFB-256-ZeroPadding",
			args: args{
				key: key256,
				fm:  "ZeroPadding",
			},
			plainText: plainOFBText,
		},

		// -----------------------------------------------------------------
		// AES-CFB-128 NoPadding
		{
			name: "AES-CFB-128-NoPadding",
			args: args{
				key: key128,
				fm:  "NoPadding",
			},
			plainText: plainOFBText,
		},
		// AES-CFB-192 NoPadding
		{
			name: "AES-CFB-192-NoPadding",
			args: args{
				key: key192,
				fm:  "NoPadding",
			},
			plainText: plainOFBText,
		},
		// AES-CFB-256 NoPadding
		{
			name: "AES-CFB-256-NoPadding",
			args: args{
				key: key256,
				fm:  "NoPadding",
			},
			plainText: plainOFBText,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			aesOFB := NewAesCFB(tt.args.key)
			cipherText, err := aesOFB.AesCFBEncrypt([]byte(tt.plainText))
			assert.NoError(t, err, fmt.Sprintf("%s encrypt failed", tt.name))
			assert.NotEmpty(t, cipherText, "cipherText should not be empty")
			// fmt.Println("==================================================================")
			// fmt.Printf("------- ciphertext: %s\n", cipherText)
			// fmt.Println("==================================================================")

			decipherPlainText, err := aesOFB.AesCFBDecrypt(cipherText)
			assert.NoError(t, err, fmt.Sprintf("%s decrypt failed", tt.name))
			assert.Equal(t, tt.plainText, decipherPlainText, fmt.Sprintf("%s decrypted text should match original", tt.name))
			// fmt.Println("==================================================================")
			// fmt.Printf("------- decipherPlainText: %s\n", decipherPlainText)
			// fmt.Println("==================================================================")
		})
	}
}
