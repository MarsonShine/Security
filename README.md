# Security
关于安全的一些零碎的知识整理

## 慢哈希（BCrypt）

概念介绍：https://coolshell.cn/articles/2078.html

慢哈希函数是指这个函数的执行事件是可以调节的哈希函数，它通常是可以调节调用次数来实现的。

.NET 的实现库地址：https://github.com/BcryptNet/bcrypt.net

我们在为哈希选择盐值时，不要选系统伪随机生成树，而是选择基于密码学的伪随机生成数，这称为 “密码学安全伪随机数”（Cryptographically Secure Pseudo-Random Number Generator）来生成一个长度与哈希值相等的随机字符串。

.NET 内置了 CSPRNG 的实现 `System.Security.Cryptography.RNGCryptoServiceProvider`