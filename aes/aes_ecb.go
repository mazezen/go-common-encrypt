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
)

type AesECB struct {
	key   []byte // secret key
	block cipher.Block
	fm    string // fill mode
}

// NewAesECB bit-words contains **AES-128**, **AES-192**, **AES-256**
// Fill method include
// - PKCS#7
// - ZeroPadding
// - NoPadding
func NewAesECB(key []byte, args ...string) *AesECB {
	b, err := aes.NewCipher(key)
	if err != nil {
		panic(fmt.Errorf("NewAesECB failed: [%+w]", err))
	}

	fillMode := fillPkcs7
	if len(args) >= 1 && args[0] != "" {
		fillMode = args[0]
	}

	return &AesECB{key: key, block: b, fm: fillMode}
}

func (this *AesECB) AesECBEnrypt(plainText []byte) (string, error) {
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

	ciphertext := make([]byte, len(padded))
	for bs, be := 0, blockSize; bs < len(padded); bs, be = bs+blockSize, be+blockSize {
		this.block.Encrypt(ciphertext[bs:be], padded[bs:be])
	}

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func (this *AesECB) AesECBDecrypt(cipherText string) (string, error) {
	cipertext, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return "", err
	}

	if len(cipertext)%this.block.BlockSize() != 0 {
		return "", fmt.Errorf("ciphertext not multiple of block size")
	}

	plaintext := make([]byte, len(cipertext))
	bs := this.block.BlockSize()
	for i := 0; i < len(cipertext); i += bs {
		this.block.Decrypt(plaintext[i:i+bs], cipertext[i:i+bs])
	}

	var plainText []byte
	switch this.fm {
	case fillPkcs7:
		plainText, err = pkcs7Unpad(plaintext)
	case fillZero:
		plainText, err = zeroUnpad(plaintext)
	case fillNo:
		if len(plaintext)%bs != 0 {
			return "", fmt.Errorf("decrypted text length is not multiple of block size (%d)", bs)
		}
		plainText = plaintext
	}

	if err != nil {
		return "", err
	}
	return string(plainText), nil
}
