package aes

import (
	"bytes"
	"fmt"
)

func fillCipher(m string, plainText []byte, blockSize int) ([]byte, error) {
	var padded []byte

	switch m {
	case fillPkcs7:
		padded = pkcs7Pad(plainText, blockSize)
	case fillZero:
		padded = zeroPad(plainText, blockSize)
	case fillNo:
		if len(plainText)%blockSize != 0 {
			return nil, fmt.Errorf("plaintext length is not a multiple of block size (%d)", blockSize)
		}
		padded = plainText
	default:
		return nil, fmt.Errorf("does not supported this mode: [%s]", m)
	}
	return padded, nil
}

func unpackDecipher(m string, decrypted []byte, blockSize int) ([]byte, error) {
	var plainText []byte
	var err error
	switch m {
	case fillPkcs7:
		plainText, err = pkcs7Unpad(decrypted)
	case fillZero:
		plainText, err = zeroUnpad(decrypted)
	case fillNo:
		if len(decrypted)%blockSize != 0 {
			return nil, fmt.Errorf("decrypted text length is not multiple of block size (%d)", blockSize)
		}
		plainText = decrypted
	}

	if err != nil {
		return nil, err
	}

	return plainText, nil
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
