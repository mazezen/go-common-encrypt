/**
* MAC, Message Authentication Code, is a small piece of additional data used to verify a message.
* In other words, it can be used to confirm the authenticity of the message - that the message came from the specified sender and has not been tampered with.
*
* The MAC value protects the data integrity and authenticity of the message by allowing the verifier who possesses the key to detect any changes to the message content.
*
* A secure MAC function, much like a cryptographic hash function, also possesses the following characteristics:
* 1. Speed: The calculation speed should be fast enough.
* 2. Determinism: For the same message and key, it should always produce the same output.
* 3. Difficult to analyze: Any minor change to the message or key should completely change the output.
* 4. Irreversibility: It should be infeasible to deduce the message and key from the MAC value in reverse.
* 5. Collision-free: It should be very difficult (or almost impossible) to find two different messages with the same hash.
*
* However, MAC algorithms have one more input value than cryptographic hash functions: the key, hence they are also known as keyed hash functions,
* which means "hash functions with encryption keys".
**/

package hash

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"io"
)

type HMac struct{}

type hmacFunc func([]byte, string) string

var hmacFuns = map[hashType]hmacFunc{
	md5i:    HMac{}.md5,
	sha1i:   HMac{}.sha1,
	sha224i: HMac{}.sha224,
	sha256i: HMac{}.sha256,
	sha384i: HMac{}.sha384,
	sha512i: HMac{}.sha512,
}

func NewHMac(i hashType, key []byte, s string) (ss string) {
	f, ok := hmacFuns[i]
	if !ok {
		return ""
	}
	return f(key, s)
}

// [HMAC-MD5]
func (hm HMac) md5(key []byte, s string) string {
	h := hmac.New(md5.New, key)
	io.WriteString(h, s)

	return hex.EncodeToString(h.Sum(nil))
}

// [HMAC-SHA1]
func (hm HMac) sha1(key []byte, s string) string {
	h := hmac.New(sha1.New, key)
	io.WriteString(h, s)

	return hex.EncodeToString(h.Sum(nil))
}

// [HMAC-SHA224]
func (hm HMac) sha224(key []byte, s string) string {
	h := hmac.New(sha256.New224, key)
	io.WriteString(h, s)

	return hex.EncodeToString(h.Sum(nil))
}

// [HMAC-SHA256]
func (hm HMac) sha256(key []byte, s string) string {
	h := hmac.New(sha256.New, key)
	io.WriteString(h, s)

	return hex.EncodeToString(h.Sum(nil))
}

// [HMAC-SHA384]
func (hm HMac) sha384(key []byte, s string) string {
	h := hmac.New(sha512.New384, key)
	io.WriteString(h, s)

	return hex.EncodeToString(h.Sum(nil))
}

// [HMAC-SHA512]
func (hm HMac) sha512(key []byte, s string) string {
	h := hmac.New(sha512.New, key)
	io.WriteString(h, s)

	return hex.EncodeToString(h.Sum(nil))
}
