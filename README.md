## go-common-encrypt

> This is a code repository dedicated to encryption. It encompasses several common encryption methods that can be directly utilized in projects.
> It includes [SHA] and [MAC] and [CSPRNG] and [AES] and [RSA] and [ECDSA]

### Install

```bash
go get github.com/mazezen/go-common-encrypt@latest
```

### <a href="https://zh.wikipedia.org/wiki/SHA%E5%AE%B6%E6%97%8F">SHA(Secure Hash Algorithm)</a>

SHA secure hash algorithm
The Secure Hash Algorithm (SHA) is a family of cryptographic hash functions, which are secure hash algorithms certified by FIPS.
It is an algorithm capable of calculating a fixed-length string (also known as a message digest) corresponding to a digital message.
And if the input messages are different, the probability of them corresponding to different strings is high

The five algorithms of the SHA family, namely SHA-1, SHA-224, SHA-256, SHA-384, and SHA-512,
were designed by the National Security Agency (NSA) and published by the National Institute of Standards and Technology (NIST);
they are U.S. government standards. The latter four are sometimes collectively referred to as SHA-2. SHA-1 is widely used in many security protocols,
including TLS and SSL, PGP, SSH, S/MIME, and IPsec, and was once considered as the successor to MD5, a previously widely used hash function.
However, the security of SHA-1 is now seriously questioned by cryptographers; although no effective attacks on SHA-2 have emerged so far,
its algorithm is still basically similar to SHA-1; therefore, some people have begun to develop other alternative hash algorithms

### <a href="https://en.wikipedia.org/wiki/HMAC"> HMAC</a>

MAC, Message Authentication Code, is a small piece of additional data used to verify a message.
In other words, it can be used to confirm the authenticity of the message - that the message came from the specified sender and has not been tampered with.

The MAC value protects the data integrity and authenticity of the message by allowing the verifier who possesses the key to detect any changes to the message content.

A secure MAC function, much like a cryptographic hash function, also possesses the following characteristics:

- Speed: The calculation speed should be fast enough.
- Determinism: For the same message and key, it should always produce the same output.
- Difficult to analyze: Any minor change to the message or key should completely change the output.
- Irreversibility: It should be infeasible to deduce the message and key from the MAC value in reverse.
- Collision-free: It should be very difficult (or almost impossible) to find two different messages with the same hash.

However, MAC algorithms have one more input value than cryptographic hash functions: the key, hence they are also known as keyed hash functions,which means "hash functions with encryption keys".

### <a href="https://en.wikipedia.org/wiki/Cryptographically_secure_pseudorandom_number_generator">CSPRNG (Cryptographically Secure Pseudo-Random Number Generator)</a>

A cryptographically secure pseudorandom number generator (CSPRNG) or cryptographic pseudorandom number generator (CPRNG) is a pseudorandom number generator (PRNG) with properties that make it suitable for use in cryptography. It is also referred to as a cryptographic random number generator (CRNG).

### <a href="https://en.wikipedia.org/wiki/Advanced_Encryption_Standard">AES (Advanced Encryption Standard)</a>

AES (Advanced Encryption Standard) is a symmetric encryption algorithm and one of the most popular encryption algorithms currently. It is standardized by the National Institute of Standards and Technology (NIST) and has become an international standard. Its encryption key length can be 128 bits, 192 bits, or 256 bits, with the 128-bit key version being the most popular. AES is a block cipher that divides plaintext into 128-bit blocks and encrypts them separately. The encryption methods include basic operations such as substitution, permutation, and linear transformation. Through multiple rounds of iterative encryption, it can provide high encryption strength while satisfying key security, thus preventing attacks from malicious attackers. AES has been widely used in many scenarios, such as data transmission, file encryption, database encryption, blockchain wallet and so on

##### AES Encryption Mode Comparison

| Mode                        | IV Required | Features                                                                   | Security                                                                 | Recommendation level        | Supported |
| :-------------------------- | :---------- | :------------------------------------------------------------------------- | :----------------------------------------------------------------------- | :-------------------------- | --------- |
| ECB (Electronic Codebook)   | ❌          | Simplest, each block is encrypted independently                            | ❌ Very low (plaintext in the same block → ciphertext in the same block) | 🚫 Not recommended          | ✅        |
| CBC (Cipher Block Chaining) | ✅          | Each block depends on the previous block, commonly used                    | ✅ High                                                                  | ⭐⭐⭐⭐ Recommended        | ✅        |
| CTR (Counter)               | ✅          | Converts AES to stream encryption, supports parallel processing            | ✅ High (if the counter does not repeat)                                 | ⭐⭐⭐⭐ Recommended        | ✅        |
| CFB (Cipher Feedback)       | ✅          | Similar to stream encryption, it can handle data smaller than a block size | ✅ High                                                                  | ⭐⭐ Average                | ✅        |
| OFB (Output Feedback)       | ✅          | Similar to CFB, vulnerable to synchronization attacks                      | ⚠️ Low                                                                   | ⭐ Average, not recommended | ✅        |

##### AES Fill Method Comparison

| Fill Method | Description                                                                | Advantage                                     | Shortcoming                                                | Recommendation level   |
| :---------- | :------------------------------------------------------------------------- | :-------------------------------------------- | :--------------------------------------------------------- | :--------------------- |
| PKCS#7      | Pads with N bytes to fill the missing N bytes                              | ✅ Universal, default in almost all libraries | ❌ Occupies extra bytes                                    | ⭐⭐⭐⭐ Recommended   |
| ZeroPadding | Pads with 0x00                                                             | ✅ Simple                                     | ❌ May cause inaccurate decryption when 0x00 is at the end | ⭐⭐ Special Scenarios |
| NoPadding   | No padding; data length must be manually guaranteed to be a multiple of 16 | ✅ No extra bytes                             | ❌ Restricted use                                          | ⭐ Fixed length only   |

### RSA

This is a lightweight Go RSA toolkit that encapsulates common operations such as key generation, PEM parsing, encryption/decryption, and signature verification.
Based on the Go standard library's crypto/rsa, it is recommended by default to use the more secure RSA-OAEP for encryption and decryption, and RSA-PSS for signing.
The package supports both:

- RSA private key generation
- DER/PEM encoding and decoding for PKCS#1, PKCS#8 / PKIX
- PEM parsing of public and private keys
- OAEP and PKCS#1 v1.5 encryption and decryption
- PSS and PKCS#1 v1.5 signature verification
  The PKCS#1 v1.5 related interfaces are primarily used for compatibility with legacy systems, and new code should prioritize the use of OAEP and PSS.

### <a href="https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm">ECDSA</a>

In cryptography, the Elliptic Curve Digital Signature Algorithm (ECDSA) offers a variant of the Digital Signature Algorithm (DSA) which uses elliptic-curve cryptography.

### Unit Test Coverage

```bash
go test -coverprofile=coverage.out ./...

ok      github.com/mazezen/go-common-encrypt/aes        0.014s  coverage: 78.8% of statements
ok      github.com/mazezen/go-common-encrypt/ecdsa      0.015s  coverage: 76.9% of statements
ok      github.com/mazezen/go-common-encrypt/hash       0.012s  coverage: 95.5% of statements
ok      github.com/mazezen/go-common-encrypt/random     0.012s  coverage: 73.5% of statements
ok      github.com/mazezen/go-common-encrypt/rsa        1.030s  coverage: 89.0% of statements
```
