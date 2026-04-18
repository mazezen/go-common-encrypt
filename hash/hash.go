/**
* SHA secure hash algorithm
*
* The Secure Hash Algorithm (SHA) is a family of cryptographic hash functions, which are secure hash algorithms certified by FIPS.
* It is an algorithm capable of calculating a fixed-length string (also known as a message digest) corresponding to a digital message.
* And if the input messages are different, the probability of them corresponding to different strings is high
*
* The five algorithms of the SHA family, namely SHA-1, SHA-224, SHA-256, SHA-384, and SHA-512,
* were designed by the National Security Agency (NSA) and published by the National Institute of Standards and Technology (NIST);
* they are U.S. government standards. The latter four are sometimes collectively referred to as SHA-2. SHA-1 is widely used in many security protocols,
* including TLS and SSL, PGP, SSH, S/MIME, and IPsec, and was once considered as the successor to MD5, a previously widely used hash function.
* However, the security of SHA-1 is now seriously questioned by cryptographers; although no effective attacks on SHA-2 have emerged so far,
* its algorithm is still basically similar to SHA-1; therefore, some people have begun to develop other alternative hash algorithms
**/

package hash

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"io"
)

type hashType uint

const (
	md5i hashType = iota
	sha1i
	sha224i
	sha256i
	sha384i
	sha512i
)

type Hash struct{}

type hashFunc func(string) string

var hashFuncs = map[hashType]hashFunc{
	md5i:    Hash{}.md5,
	sha1i:   Hash{}.sha1,
	sha224i: Hash{}.sha224,
	sha256i: Hash{}.sha256,
	sha384i: Hash{}.sha384,
	sha512i: Hash{}.sha512,
}

func NewHash(i hashType, s string) (ss string) {
	f, ok := hashFuncs[i]
	if !ok {
		return ""
	}
	return f(s)
}

// [MD5] is cryptographically broken and should not be used for secure applications.
func (hash Hash) md5(s string) string {
	h := md5.New()
	io.WriteString(h, s)

	return fmt.Sprintf("%x", h.Sum(nil))
}

// [SHA-1] is cryptographically broken and should not be used for secure applications .
func (hash Hash) sha1(s string) string {
	h := sha1.New()
	io.WriteString(h, s)

	return fmt.Sprintf("%x", h.Sum(nil))
}

// [SHA-224]
func (hash Hash) sha224(s string) string {
	h := sha256.New224()
	io.WriteString(h, s)

	return fmt.Sprintf("%x", h.Sum(nil))
}

// [sHA-256]
func (hash Hash) sha256(s string) string {
	h := sha256.New()
	io.WriteString(h, s)

	return fmt.Sprintf("%x", h.Sum(nil))
}

// [SHA-384]
func (hash Hash) sha384(s string) string {
	h := sha512.New384()
	io.WriteString(h, s)

	return fmt.Sprintf("%x", h.Sum(nil))
}

// [SHA-512]
func (hash Hash) sha512(s string) string {
	h := sha512.New()
	io.WriteString(h, s)

	return fmt.Sprintf("%x", h.Sum(nil))
}
