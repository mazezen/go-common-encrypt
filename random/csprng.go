/**
* CSPRNG (Cryptographically Secure Pseudo-Random Number Generator) is a specialized
* pseudo-random number generator (PRNG) designed for cryptography and
* security-sensitive applications. The random numbers it generates not only
* appear "random" statistically, but also possess strong resistance to prediction.
* Even if an attacker knows part of the output or internal state, it is difficult to
* infer the subsequent content
*
* Application Scenario: CSPRNG is a fundamental component of cryptography, used for:
*
* 1. Generate encryption keys (symmetric/asymmetric keys).
* 2. Initialization vector (IV) and Nonce (to prevent replay attacks).
* 3. Session token, password salt, CSRF token.
* 4. Digital signatures, TLS/SSL handshakes, blockchain private keys, etc.
*
* https://en.wikipedia.org/wiki/Cryptographically_secure_pseudorandom_number_generator
**/

package random

import (
	"crypto/rand"
	"encoding/hex"
	"math/big"
)

// RandomBytes generate a random string of n bytes
func RandomBytes(n uint) ([]byte, error) {
	if n <= 0 {
		return []byte(""), ErrN
	}

	k := make([]byte, n)
	_, err := rand.Read(k)
	if err != nil {
		return []byte(""), err
	}

	return k, nil
}

// RandomHex generate a specified number(n) of strings randomly
func RandomHex(n uint) (string, error) {
	nb := n / 2
	b, err := RandomBytes(nb)
	if err != nil {
		return "", nil
	}
	return hex.EncodeToString(b), nil
}

var charset = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=")

// RandomPassword generate s specified number(n) of strings randomly for password
func RandomPassword(n int) (string, error) {
	if n <= 0 {
		return "", ErrN
	}
	password := make([]rune, n)
	for i := range password {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", err
		}
		password[i] = charset[n.Int64()]
	}
	return string(password), nil
}
