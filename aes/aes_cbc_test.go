package aes

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewAesCBC(t *testing.T) {
	type args struct {
		k []byte
		n uint
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "Test AES-CBC-PKCS7 AES-128", // AES-192, or AES-256.
			args: args{
				k: []byte("1ockKIb8Kg6s4uc8"),
				n: 16,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			aesCBC := NewAesCBC(tt.args.k, tt.args.n)
			plainText := `AES (Advanced Encryption Standard) 是一种对称加密算法，也是当前最流行的加密算法之一，由美国国家标准和技术研究所 (NIST) 标准化，已经成为了国际标准。它的加密密钥长度可以为 128 位、192 位或 256 位，其中 128 位密钥版本最为流行。AES 是一种分组密码，将明文分成 128 位一组，然后分别进行加密，加密方式包括替换、置换、线性变换等基本操作。通过多轮迭代加密，在满足密钥安全性的前提下，能够提供很高的加密强度，以防止恶意攻击者的攻击。在许多场景下，AES 已经被广泛应用，例如数据传输、文件加密、数据库加密等等。`
			cipherText, err := aesCBC.AesCBCCipher([]byte(plainText))
			assert.NoError(t, err, "aes-cbc-pkcs7 aes-128 encrypt failed")
			assert.NotEmpty(t, cipherText, "cipherText should not be empty")

			fmt.Println(cipherText)
			fmt.Println("==================================================================")

			decipherPlainText, err := aesCBC.AesCBDDecipher(cipherText)
			assert.NoError(t, err, "aes-cbc-pkcs7 aes-128 decrypt failed")
			assert.Equal(t, plainText, decipherPlainText, "decrypted text should match original")

			fmt.Println(decipherPlainText)
		})
	}
}
