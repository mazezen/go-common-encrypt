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
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"

	"github.com/mazezen/go-common-encrypt/random"
)

const (
	// Copyright 2009 The Go Authors
	// AES-128 has 128-bit keys, 10 rounds, and uses 11 128-bit round keys
	// (11×128÷32 = 44 32-bit words).

	// AES-192 has 192-bit keys, 12 rounds, and uses 13 128-bit round keys
	// (13×128÷32 = 52 32-bit words).

	// AES-256 has 256-bit keys, 14 rounds, and uses 15 128-bit round keys
	// (15×128÷32 = 60 32-bit words).

	aes128KeySize uint = 16
	aes192KeySize uint = 24
	aes256KeySize uint = 32
)

type AesCBC struct {
	// ======================= CBC =====================
	key   []byte // secret key
	block cipher.Block
}

// NewAesCBC bit-words contains **AES-128**, **AES-192**, **AES-256**
// Fill method include
// - PKCS#7
// - ZeroPadding
// - NoPadding
func NewAesCBC(k []byte, n uint) *AesCBC {
	b, err := aes.NewCipher(k)
	if err != nil {
		panic(fmt.Errorf("NewAesCBC failed: [%+w]", err))
	}
	switch n {
	case aes128KeySize, aes192KeySize, aes256KeySize:
	default:
		panic(aes.KeySizeError(n))
	}

	return &AesCBC{key: k, block: b}
}

func (this *AesCBC) AesCBCCipher(plainText []byte) (string, error) {
	blockSize := this.block.BlockSize()
	padded := this.pkcs7Pad(plainText, blockSize)

	// Offset IV Use CSPRNG (Cryptographically Secure Pseudo-Random Number Generator)
	iv, err := random.RandomBytes(uint(blockSize))
	if err != nil {
		return "", fmt.Errorf("generate random IV failed: %w", err)
	}
	fmt.Println("===========", iv)

	mode := cipher.NewCBCEncrypter(this.block, iv)
	encrypted := make([]byte, len(padded))
	mode.CryptBlocks(encrypted, padded)

	// IV + ciphertext
	final := append(iv, encrypted...)
	return base64.StdEncoding.EncodeToString(final), nil
}

func (this *AesCBC) AesCBDDecipher(cipherText string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return "", err
	}

	blockSize := this.block.BlockSize()
	if len(b) < blockSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	// The first blockSize bytes are the IV
	iv := b[:blockSize]
	cipherBytes := b[blockSize:]

	if len(cipherBytes)%blockSize != 0 {
		return "", fmt.Errorf("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(this.block, iv)
	decrypted := make([]byte, len(cipherBytes))
	mode.CryptBlocks(decrypted, cipherBytes)

	plainText, err := this.pkcs7Unpad(decrypted)
	if err != nil {
		return "", err
	}

	return string(plainText), nil
}

func (this *AesCBC) pkcs7Pad(plainText []byte, blockSize int) []byte {
	padding := blockSize - len(plainText)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(plainText, padText...)
}

func (this *AesCBC) pkcs7Unpad(plainText []byte) ([]byte, error) {
	length := len(plainText)
	if length == 0 {
		return nil, fmt.Errorf("invalid padding size")
	}

	padding := int(plainText[length-1])
	if padding > length || padding == 0 {
		return nil, fmt.Errorf("invalid padding size")
	}

	for _, v := range plainText[length-padding:] {
		if int(v) != padding {
			return nil, fmt.Errorf("invalid padding")
		}
	}

	return plainText[:length-padding], nil
}
