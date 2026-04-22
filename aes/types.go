package aes

import "crypto/cipher"

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

type base struct {
	key   []byte // secret key
	block cipher.Block
	fm    string // fill mode
}
