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

	// aes128KeySize uint = 16
	// aes192KeySize uint = 24
	// aes256KeySize uint = 32

	fillPkcs7 string = "PKCS#7" // default fill method
	fillZero  string = "ZeroPadding"
	fillNo    string = "NoPadding"
)

type AesCBC struct {
	key   []byte // secret key
	block cipher.Block
	fm    string // fill mode
}

// NewAesCBC bit-words contains **AES-128**, **AES-192**, **AES-256**
// Fill method include
// - PKCS#7
// - ZeroPadding
// - NoPadding
func NewAesCBC(k []byte, args ...string) *AesCBC {
	b, err := aes.NewCipher(k)
	if err != nil {
		panic(fmt.Errorf("NewAesCBC failed: [%+w]", err))
	}

	fillMode := fillPkcs7
	if len(args) >= 1 && args[0] != "" {
		fillMode = args[0]
	}

	return &AesCBC{key: k, block: b, fm: fillMode}
}

func (this *AesCBC) AesCBCCipher(plainText []byte) (string, error) {
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

	mode := cipher.NewCBCEncrypter(this.block, iv)
	encrypted := make([]byte, len(padded))
	mode.CryptBlocks(encrypted, padded)

	// IV + ciphertext
	final := append(iv, encrypted...)
	return base64.StdEncoding.EncodeToString(final), nil
}

func (this *AesCBC) AesCBCDecipher(cipherText string) (string, error) {
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
		return "", err
	}

	return string(plainText), nil
}

// pkcs7Pad Recommended
func pkcs7Pad(plainText []byte, blockSize int) []byte {
	padding := blockSize - len(plainText)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(plainText, padText...)
}

func pkcs7Unpad(plainText []byte) ([]byte, error) {
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

// zeroPad May cause inaccurate decryption when 0x00 is at the end.
// eg: plaintext: hello\x00\x00 deciphertext: hello\x00\x0
func zeroPad(plainText []byte, blockSize int) []byte {
	padding := blockSize - len(plainText)%blockSize
	if padding == blockSize {
		return plainText
	}
	padText := bytes.Repeat([]byte{0}, padding)
	return append(plainText, padText...)
}

func zeroUnpad(plainText []byte) ([]byte, error) {
	return bytes.TrimFunc(plainText, func(r rune) bool {
		return r == 0
	}), nil
}
