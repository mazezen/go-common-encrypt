## go-common-encrypt

> 这是一个专门用于加密的代码库。它包含了多种常见的加密方法，可以直接在项目中使用。 [SHA] 和 [MAC] 和 [CSPRNG] 和 [AES] > 和 [RSA]

### 安装

```bash
go get github.com/mazezen/go-common-encrypt@latest
```

### <a href="https://zh.wikipedia.org/wiki/SHA%E5%AE%B6%E6%97%8F">SHA(安全散列算法)</a>

SHA安全散列算法
安全散列算法（英语：Secure Hash Algorithm，缩写为SHA）是一个密码散列函数家族，是FIPS所认证的安全散列算法。能计算出一个数字消息所对应到的，长度固定的字符串（又称消息摘要）的算法。且若输入的消息不同，它们对应到不同字符串的机率很高

SHA家族的五个算法，分别是SHA-1、SHA-224、SHA-256、SHA-384，和SHA-512，由美国国家安全局（NSA）所设计，并由美国国家标准与技术研究院（NIST）发布；是美国的政府标准。后四者有时并称为SHA-2。SHA-1在许多安全协定中广为使用，包括TLS和SSL、PGP、SSH、S/MIME和IPsec，曾被视为是MD5（更早之前被广为使用的杂凑函数）的后继者。但SHA-1的安全性如今被密码学家严重质疑；虽然至今尚未出现对SHA-2有效的攻击，它的算法跟SHA-1基本上仍然相似；因此有些人开始发展其他替代的杂凑算法。

### <a href="https://en.wikipedia.org/wiki/HMAC"> HMAC</a>

MAC 消息认证码，即 Message Authentication Code，是用于验证消息的一小段附加数据。换句话说， 能用它确认消息的真实性——消息来自指定的发件人并且没有被篡改。

MAC 值通过允许拥有密钥的验证者检测消息内容的任何更改来保护消息的数据完整性及其真实性。

一个安全的 MAC 函数，跟加密哈希函数非常类似，也拥有如下特性：

- 快速：计算速度要足够快
- 确定性：对同样的消息跟密钥，应该总是产生同样的输出
- 难以分析：对消息或密钥的任何微小改动，都应该使输出完全发生变化
- 不可逆：从 MAC 值逆向演算出消息跟密钥应该是不可行的。
- 无碰撞：找到具有相同哈希的两条不同消息应该非常困难（或几乎不可能）

但是 MAC 算法比加密哈希函数多一个输入值：密钥，因此也被称为 keyed hash functions，即「加密钥的哈希函数」。

### <a href="https://en.wikipedia.org/wiki/Cryptographically_secure_pseudorandom_number_generator">CSPRNG (密码学安全的伪随机数生成器)</a>

密码学安全伪随机数生成器 （ CSPRNG ）或密码学伪随机数生成器 （ CPRNG ）是一种伪随机数生成器 （PRNG），其特性使其适用于密码学 。它也被称为密码学随机数生成器 （ CRNG ）。

### <a href="https://en.wikipedia.org/wiki/Advanced_Encryption_Standard">AES (Advanced Encryption Standard)</a>

AES（高级加密标准）是一种对称加密算法，也是当前最流行的加密算法之一。它由美国国家标准与技术研究院（NIST）制定，已成为国际标准。其加密密钥长度可以是128位、192位或256位，其中128位密钥版本最为流行。AES是一种分组密码，它将明文分成128位的块，并对每个块分别进行加密。加密方法包括替换、置换和线性变换等基本操作。通过多轮迭代加密，它能在满足密钥安全性的同时提供高加密强度，从而防止恶意攻击者的攻击。AES已广泛应用于许多场景，如数据传输、文件加密、数据库加密、区块链钱包等等

##### AES 加密模式对比

| 模式                        | 是否需要 IV | 特点                             | 安全性                       | 推荐程度        | 是否支持 |
| :-------------------------- | :---------- | :------------------------------- | :--------------------------- | :-------------- | -------- |
| ECB (Electronic Codebook)   | ❌          | 最简单，每个分组独立加密         | ❌ 极低（同块明文→同块密文） | 🚫 不推荐       | ✅       |
| CBC (Cipher Block Chaining) | ✅          | 每个分组依赖上个分组，常用       | ✅ 高                        | ⭐⭐⭐⭐ 推荐   | ✅       |
| CTR (Counter)               | ✅          | 将 AES 变成流加密，支持并行      | ✅ 高（若计数器不重复）      | ⭐⭐⭐⭐ 推荐   | ❌       |
| CFB (Cipher Feedback)       | ✅          | 类似流加密，能处理小于分组的数据 | ✅ 较高                      | ⭐⭐ 一般       | ❌       |
| OFB (Output Feedback)       | ✅          | 与 CFB 类似，易受同步攻击        | ⚠️ 较低                      | ⭐ 一般，不推荐 | ❌       |

##### AES 填充方式对比

| 填充方式    | 说明                                   | 优点                    | 缺点                          | 推荐程度        |
| :---------- | :------------------------------------- | :---------------------- | :---------------------------- | :-------------- |
| PKCS#7      | 用缺少字节数 N 填充 N 个字节           | ✅ 通用，几乎所有库默认 | ❌ 占用额外字节               | ⭐⭐⭐⭐ 推荐   |
| ZeroPadding | 用 0x00 填充                           | ✅ 简单                 | ❌ 末尾有 0x00 时可能解密不准 | ⭐⭐ 特殊场景   |
| NoPadding   | 不填充，需手动保证数据长度是 16 的倍数 | ✅ 无额外字节           | ❌ 使用受限                   | ⭐ 仅限固定长度 |

### RSA

这是一个轻量的 Go RSA 工具包，封装了密钥生成、PEM 解析、加解密和签名验签等常见操作。它以 Go 标准库 crypto/rsa 为基础，默认推荐使用更安全的 RSA-OAEP 做加解密、RSA-PSS 做签名。包内同时支持：

- RSA 私钥生成
- PKCS#1、PKCS#8 / PKIX 的 DER / PEM 编解码

* 公私钥 PEM 解析
* OAEP 与 PKCS#1 v1.5 加解密
* PSS 与 PKCS#1 v1.5 签名验签

其中 PKCS#1 v1.5 相关接口主要用于兼容旧系统，新代码应优先使用 OAEP 和 PSS。

### 单测覆盖率

```bash
go test -cover ./...

ok  	github.com/mazezen/go-common-encrypt/aes	0.012s	coverage: 78.8% of statements
ok  	github.com/mazezen/go-common-encrypt/hash	0.009s	coverage: 95.5% of statements
ok  	github.com/mazezen/go-common-encrypt/random	0.012s	coverage: 73.5% of statements
```
