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
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"

	"github.com/mazezen/go-common-encrypt/random"
)

type AesCFB struct {
	base
}

func NewAesCFB(k []byte, args ...string) *AesCFB {
	b, err := aes.NewCipher(k)
	if err != nil {
		panic(fmt.Errorf("NewAesCFN failed: [%+w]", err))
	}

	fillMode := fillPkcs7
	if len(args) >= 1 && args[0] != "" {
		fillMode = args[0]
	}

	return &AesCFB{base: base{key: k, block: b, fm: fillMode}}
}

// AesCFBEncrypt
//
// Deprecated: CFB mode is not authenticated, which generally enables active
// attacks to manipulate and recover the plaintext
func (this *AesCFB) AesCFBEncrypt(plainText []byte) (string, error) {
	blockSize := this.block.BlockSize()

	padded, err := fillCipher(this.fm, plainText, blockSize)
	if err != nil {
		return "", nil
	}

	// Offset IV Use CSPRNG (Cryptographically Secure Pseudo-Random Number Generator)
	iv, err := random.RandomBytes(uint(blockSize))
	if err != nil {
		return "", fmt.Errorf("generate random IV failed: %w", err)
	}

	stream := cipher.NewCFBEncrypter(this.block, iv)
	encrypted := make([]byte, len(padded))
	stream.XORKeyStream(encrypted, padded)

	final := append(iv, encrypted...)
	return base64.StdEncoding.EncodeToString(final), nil
}

// AesCFBDecrypt
//
// Deprecated: CFB mode is not authenticated, which generally enables active
// attacks to manipulate and recover the plaintext
func (this *AesCFB) AesCFBDecrypt(cipherText string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return "", err
	}

	blockSize := this.block.BlockSize()
	if len(b) < blockSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	// The first blickSize bytes are the IV
	iv := b[:blockSize]
	cipherBytes := b[blockSize:]

	if len(cipherBytes)%blockSize != 0 {
		return "", fmt.Errorf("ciphertext is not a multiple of the block size")
	}

	Stream := cipher.NewCFBDecrypter(this.block, iv)
	decrypted := make([]byte, len(cipherBytes))
	Stream.XORKeyStream(decrypted, cipherBytes)

	plainText, err := unpackDecipher(this.fm, decrypted, blockSize)
	if err != nil {
		return "", fmt.Errorf("unpack decrypt err: [%+w]", err)
	}

	return string(plainText), nil
}
