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
	"encoding/base64"
	"fmt"
)

type AesECB struct {
	base
}

// NewAesECB bit-words contains **AES-128**, **AES-192**, **AES-256**
// Fill method include
// - PKCS#7
// - ZeroPadding
// - NoPadding
func NewAesECB(k []byte, args ...string) *AesECB {
	b, err := aes.NewCipher(k)
	if err != nil {
		panic(fmt.Errorf("NewAesECB failed: [%+w]", err))
	}

	fillMode := fillPkcs7
	if len(args) >= 1 && args[0] != "" {
		fillMode = args[0]
	}

	return &AesECB{base: base{key: k, block: b, fm: fillMode}}
}

func (this *AesECB) AesECBEnrypt(plainText []byte) (string, error) {
	blockSize := this.block.BlockSize()

	padded, err := fillCipher(this.fm, plainText, blockSize)
	if err != nil {
		return "", nil
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

	plainText, err := unpackDecipher(this.fm, plaintext, bs)
	if err != nil {
		return "", fmt.Errorf("unpack decrypt err: [%+w]", err)
	}

	return string(plainText), nil
}
