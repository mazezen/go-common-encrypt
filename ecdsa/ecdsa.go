package ecdsa

import (
	"crypto/ecdsa"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
)

// SignWithMD5ToBase64 对输入数据做 MD5 摘要后，使用 ECDSA 私钥签名并返回 Base64 编码结果。
func SignWithMD5ToBase64(priv *ecdsa.PrivateKey, data []byte) (string, error) {
	hash := md5.Sum(data)
	b, err := ecdsa.SignASN1(rand.Reader, priv, hash[:])
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// VerifySignWithMD5FromBase64 对输入数据做 MD5 摘要，并校验 Base64 编码的 ECDSA ASN.1 签名。
func VerifySignWithMD5FromBase64(pub *ecdsa.PublicKey, data []byte, sig string) bool {
	signature, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		return false
	}
	hash := md5.Sum(data)
	return ecdsa.VerifyASN1(pub, hash[:], signature)
}

// SignWithSha1ToBase64 对输入数据做 SHA-1 摘要后，使用 ECDSA 私钥签名并返回 Base64 编码结果。
func SignWithSha1ToBase64(priv *ecdsa.PrivateKey, data []byte) (string, error) {
	hash := sha1.Sum(data)
	b, err := ecdsa.SignASN1(rand.Reader, priv, hash[:])
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// VerifySignWithSha1FromBase64 对输入数据做 SHA-1 摘要，并校验 Base64 编码的 ECDSA ASN.1 签名。
func VerifySignWithSha1FromBase64(pub *ecdsa.PublicKey, data []byte, sig string) bool {
	signature, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		return false
	}
	hash := sha1.Sum(data)
	return ecdsa.VerifyASN1(pub, hash[:], signature)
}

// SignWithSha224ToBase64 对输入数据做 SHA-224 摘要后，使用 ECDSA 私钥签名并返回 Base64 编码结果。
func SignWithSha224ToBase64(priv *ecdsa.PrivateKey, data []byte) (string, error) {
	hash := sha256.Sum224(data)
	b, err := ecdsa.SignASN1(rand.Reader, priv, hash[:])
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// VerifySignWithSha224FromBase64 对输入数据做 SHA-224 摘要，并校验 Base64 编码的 ECDSA ASN.1 签名。
func VerifySignWithSha224FromBase64(pub *ecdsa.PublicKey, data []byte, sig string) bool {
	signature, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		return false
	}
	hash := sha256.Sum224(data)
	return ecdsa.VerifyASN1(pub, hash[:], signature)
}

// SignWithSha256ToBase64 对输入数据做 SHA-256 摘要后，使用 ECDSA 私钥签名并返回 Base64 编码结果。
func SignWithSha256ToBase64(priv *ecdsa.PrivateKey, data []byte) (string, error) {
	hash := sha256.Sum256(data)
	b, err := ecdsa.SignASN1(rand.Reader, priv, hash[:])
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// VerifySignWithSha256FromBase64 对输入数据做 SHA-256 摘要，并校验 Base64 编码的 ECDSA ASN.1 签名。
func VerifySignWithSha256FromBase64(pub *ecdsa.PublicKey, data []byte, sig string) bool {
	signature, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		return false
	}
	hash := sha256.Sum256(data)
	return ecdsa.VerifyASN1(pub, hash[:], signature)
}

// SignWithSha512ToBase64 对输入数据做 SHA-512 摘要后，使用 ECDSA 私钥签名并返回 Base64 编码结果。
func SignWithSha512ToBase64(priv *ecdsa.PrivateKey, data []byte) (string, error) {
	hash := sha512.Sum512(data)
	b, err := ecdsa.SignASN1(rand.Reader, priv, hash[:])
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// VerifySignWithSha512FromBase64 对输入数据做 SHA-512 摘要，并校验 Base64 编码的 ECDSA ASN.1 签名。
func VerifySignWithSha512FromBase64(pub *ecdsa.PublicKey, data []byte, sig string) bool {
	signature, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		return false
	}
	hash := sha512.Sum512(data)
	return ecdsa.VerifyASN1(pub, hash[:], signature)
}
