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

type AesOFB struct {
	key   []byte
	block cipher.Block
	fm    string
}

// NewAesOFB bit-words contains **AES-128**, **AES-192**, **AES-256**
//
// Deprecated: OFB mode is not authenticated, which generally enables active
// attacks to manipulate and recover the plaintext
// Fill method include
// - PKCS#7
// - ZeroPadding
// - NoPadding
func NewAesOFB(k []byte, args ...string) *AesOFB {
	b, err := aes.NewCipher(k)
	if err != nil {
		panic(fmt.Errorf("NewAesOFB failed: [%+w]", err))
	}

	fillMode := fillPkcs7
	if len(args) >= 1 && args[0] != "" {
		fillMode = args[0]
	}

	return &AesOFB{key: k, block: b, fm: fillMode}
}

// AesOFBEncrypt
//
// Deprecated: OFB mode is not authenticated, which generally enables active
// attacks to manipulate and recover the plaintext
func (this *AesOFB) AesOFBEncrypt(plainText []byte) (string, error) {
	blockSize := this.block.BlockSize()

	var padded []byte
	switch this.fm {
	case fillPkcs7:
		padded = pkcs7Pad(plainText, blockSize)
	case fillZero:
		padded = zeroPad(plainText, blockSize)
	case fillNo:
		if len(plainText)%blockSize != 0 {
			return "", fmt.Errorf("plaintext length is not a multiple of block size (%d)", blockSize)
		}
		padded = plainText
	default:
		return "", fmt.Errorf("does not supported this mode: [%s]", this.fm)
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

// AesOFBDecrypt
//
// Deprecated: OFB mode is not authenticated, which generally enables active
// attacks to manipulate and recover the plaintext
func (this *AesOFB) AesOFBDecrypt(cipherText string) (string, error) {
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

	var plainText []byte
	switch this.fm {
	case fillPkcs7:
		plainText, err = pkcs7Unpad(decrypted)
	case fillZero:
		plainText, err = zeroUnpad(decrypted)
	case fillNo:
		if len(decrypted)%blockSize != 0 {
			return "", fmt.Errorf("decrypted text length is not multiple of block size (%d)", blockSize)
		}
		plainText = decrypted
	}

	if err != nil {
		return "", fmt.Errorf("unpack decrypt err: [%+w]", err)
	}

	return string(plainText), nil
}
