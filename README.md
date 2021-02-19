# Security
关于安全的一些零碎的知识整理

## 慢哈希（BCrypt）

概念介绍：https://coolshell.cn/articles/2078.html

慢哈希函数是指这个函数的执行事件是可以调节的哈希函数，它通常是可以调节调用次数来实现的。

.NET 的实现库地址：https://github.com/BcryptNet/bcrypt.net

我们在为哈希选择盐值时，不要选系统伪随机生成树，而是选择基于密码学的伪随机生成数，这称为 “密码学安全伪随机数”（Cryptographically Secure Pseudo-Random Number Generator）来生成一个长度与哈希值相等的随机字符串。

.NET 内置了 CSPRNG 的实现 `System.Security.Cryptography.RNGCryptoServiceProvider`

## 一次性密码（One Time-Password,OTP）

即基于 hmac 的一次性密码(HOTP)算法，正如 [RFC 4226](https://tools.ietf.org/html/rfc4226) 中定义的，以支持基于时间的移动因子。HOTP 算法基于事件的 OTP 算法，其中的移动因子是一个事件计数器。目前的工作基于一个时间值的移动因子。OTP 算法基于时间的变体提供短期的 OTP 值，这是增强安全性所需要的。

该算法可用于广泛的网络应用，从远程虚拟专用（VPN）接入和 Wi-Fi 网络登录到面向事务的 Web 应用程序。作者认为，通过实现商业和开源实现之间的互操作性，一种共同和共享的算法将会促进互联网上双因素认证的采用。

HOTP 是基于 HMAC-SHA-1 算法并且应用了递增计数值来表示 HMAC 计算的值：

```
HOTP(K,C) = Truncate(HMAC-SHA-1(K,C))
```

其中 Truncate 函数表示将 HMAC-SHA-1 值转换成一个 HTOP 值。K，C 分别表示共享密钥以及计数器值。

TOTP 是基于时间算法的变种，其中由时间引用和时间步长派生的值 T 在 HOTP 计算中取代计数器 C。

TOTP 可以使用 HMAC-SHA-256 或 HMAC-SHA-512 函数来实现，在 HOTP 的实现中是基于 SHA-256 或 SHA-512 哈希函数而不是 HMAC-SHA-1 函数

更多相关的详情只是可见：[rfc6238](https://tools.ietf.org/html/rfc6238)

.NET 内置了相关的 api，详情可见：[TotpAuthenticationService](https://github.com/MarsonShine/AlgorithmsLearningStudy/blob/2fa762ccf4c72593c4a76de6b0ce1547db9b8885/Encryptions/TotpAuthenticationService.cs)