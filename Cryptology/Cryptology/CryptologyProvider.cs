using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Cryptology
{
    /// <summary>
    /// 代码来源：https://github.com/dotnetcore/Util/blob/f73da0060a9882a28f1aa2fb03d80b9ae445d21a/src/Util/Helpers/Encrypt.cs
    /// </summary>
    public class CryptologyProvider
    {
        private const string key = "QaP1AF8utIarcBqdhYTZpVGbiNQ9M6IL";
        public static class AesCrypt
        {
            /// <summary>
            /// 128 位零向量
            /// </summary>
            private static byte[] _iv;
            public static byte[] IV
            {
                get
                {
                    if (_iv == null)
                    {
                        var size = 16;
                        _iv = new byte[size];
                        for (int i = 0; i < size; i++)
                            _iv[i] = 0;
                    }
                    return _iv;
                }
            }

            #region AES加密
            public static string Encrypt(string value)
            {
                return AesEnCrypt(value, key);
            }

            public static string AesEnCrypt(string value, string key)
            {
                return AesEnCrypt(value, key, Encoding.UTF8);
            }

            public static string AesEnCrypt(string value, string key, Encoding encoding, CipherMode cipherMode = CipherMode.CBC)
            {
                if (string.IsNullOrWhiteSpace(value) || string.IsNullOrWhiteSpace(key))
                    return string.Empty;
                var rijndaelManaged = CreateRijndaelManaged(key, encoding, cipherMode);
                using (var transform = rijndaelManaged.CreateEncryptor(rijndaelManaged.Key, rijndaelManaged.IV))
                {
                    return GetEncryptResult(value, encoding, transform);
                }
            }

            private static string GetEncryptResult(string value, Encoding encoding, ICryptoTransform transform)
            {
                var bytes = encoding.GetBytes(value);
                var result = transform.TransformFinalBlock(bytes, 0, bytes.Length);

                return Convert.ToBase64String(result);
            }

            public static string AesEnCrypt(string value, string key, string iv, Encoding encoding, CipherMode cipherMode = CipherMode.CBC)
            {
                if (string.IsNullOrWhiteSpace(value) || string.IsNullOrWhiteSpace(key))
                    return string.Empty;
                var rijndaelManaged = CreateRijndaelManaged(key, iv, encoding, cipherMode);
                using (var transform = rijndaelManaged.CreateDecryptor(rijndaelManaged.Key, rijndaelManaged.IV))
                {
                    return GetEncryptResult(value, encoding, transform);
                }
            }
            #endregion

            #region AES解密
            public static string Decrypt(string value)
            {
                return AesDecrypt(value, key);
            }

            public static string AesDecrypt(string value, string key)
            {
                return AesDecrypt(value, key, Encoding.UTF8);
            }

            public static string AesDecrypt(string value, string key, Encoding encoding, CipherMode cipherMode = CipherMode.CBC)
            {
                if (string.IsNullOrWhiteSpace(value) || string.IsNullOrWhiteSpace(key))
                    return string.Empty;
                var rijndaelManaged = CreateRijndaelManaged(key, encoding, cipherMode);
                using (var transform = rijndaelManaged.CreateDecryptor(rijndaelManaged.Key, rijndaelManaged.IV))
                {
                    return GetDecryptResult(value, encoding, transform);
                }
            }
            #endregion

            /// <summary>
            /// 创建Des加密服务提供程序
            /// </summary>
            private static TripleDESCryptoServiceProvider CreateDesProvider(string key)
            {
                return new TripleDESCryptoServiceProvider { Key = Encoding.ASCII.GetBytes(key), Mode = CipherMode.ECB, Padding = PaddingMode.PKCS7 };
            }

            private static string GetDecryptResult(string value, Encoding encoding, ICryptoTransform transform)
            {
                var bytes = Convert.FromBase64String(value);
                var result = transform.TransformFinalBlock(bytes, 0, bytes.Length);
                return encoding.GetString(result);
            }

            /// <summary>
            /// 创建RijndaelManaged
            /// </summary>
            private static RijndaelManaged CreateRijndaelManaged(string key, Encoding encoding, CipherMode cipherMode = CipherMode.CBC)
            {
                return CreateRijndaelManaged(key, null, encoding, cipherMode);
            }

            /// <summary>
            /// 创建RijndaelManaged
            /// </summary>
            private static RijndaelManaged CreateRijndaelManaged(string key, string iv, Encoding encoding, CipherMode cipherMode = CipherMode.CBC)
            {
                if (!string.IsNullOrWhiteSpace(iv))
                    _iv = encoding.GetBytes(iv.Substring(0, 16));

                return new RijndaelManaged
                {
                    Key = encoding.GetBytes(key),
                    Mode = cipherMode,
                    Padding = PaddingMode.PKCS7,
                    IV = IV
                };
            }
        }

        public static class DesCrypt
        {
            public static string Encrypt(string value)
            {
                return EnCrypt(value, key);
            }

            public static string EnCrypt(string value, string key)
            {
                return EnCrypt(value, key, Encoding.UTF8);
            }
            /// <summary>
            /// Des 加密
            /// </summary>
            /// <param name="value"></param>
            /// <param name="key">24 位密钥</param>
            /// <param name="encoding"></param>
            /// <returns></returns>
            public static string EnCrypt(string value, string key, Encoding encoding)
            {
                if (!ValidateDesValueAndKey(value, key))
                {
                    return "";
                }
                using var transform = CreateDesProvider(key).CreateDecryptor();
                return GetEncryptResult(value, encoding, transform);
            }

            public static string Decrypt(string value) => Decrypt(value, key);

            public static string Decrypt(string value, string key) => Decrypt(value, key, Encoding.UTF8);

            public static string Decrypt(string value, string key, Encoding encoding)
            {
                if (!ValidateDesValueAndKey(value, key))
                    return string.Empty;
                using (var transform = CreateDesProvider(key).CreateDecryptor())
                {
                    return GetDecryptResult(value, encoding, transform);
                }
            }

            private static string GetDecryptResult(string value, Encoding encoding, ICryptoTransform transform)
            {
                var bytes = System.Convert.FromBase64String(value);
                var result = transform.TransformFinalBlock(bytes, 0, bytes.Length);
                return encoding.GetString(result);
            }

            private static bool ValidateDesValueAndKey(string value,string key)
            {
                if (string.IsNullOrWhiteSpace(value) || string.IsNullOrWhiteSpace(key))
                    return false;
                return key.Length == 24;
            }

            private static TripleDESCryptoServiceProvider CreateDesProvider(string key)
            {
                return new TripleDESCryptoServiceProvider { Key = Encoding.ASCII.GetBytes(key), Mode = CipherMode.ECB, Padding = PaddingMode.PKCS7 };
            }

            private static string GetEncryptResult(string value, Encoding encoding, ICryptoTransform transform)
            {
                var bytes = encoding.GetBytes(value);
                var result = transform.TransformFinalBlock(bytes, 0, bytes.Length);
                return System.Convert.ToBase64String(result);
            }
        }

        public static class Md5
        {
            public static string Encrypt(string value, Encoding encoding)
            {
                if (string.IsNullOrWhiteSpace(value))
                    return string.Empty;
                var md5 = new MD5CryptoServiceProvider();
                string result;
                try
                {
                    var hash = md5.ComputeHash(encoding.GetBytes(value));
                    result = BitConverter.ToString(hash);
                }
                finally
                {
                    md5.Clear();
                }
                return result.Replace("-", "");
            }
        }

        public static class HmacSha
        {
            #region HmacSha256加密

            /// <summary>
            /// HMACSHA256加密
            /// </summary>
            /// <param name="value">值</param>
            /// <param name="key">密钥</param>
            public static string HmacSha256(string value, string key)
            {
                return HmacSha256(value, key, Encoding.UTF8);
            }

            /// <summary>
            /// HMACSHA256加密
            /// </summary>
            /// <param name="value">值</param>
            /// <param name="key">密钥</param>
            /// <param name="encoding">字符编码</param>
            public static string HmacSha256(string value, string key, Encoding encoding)
            {
                if (string.IsNullOrWhiteSpace(value) || string.IsNullOrWhiteSpace(key))
                    return string.Empty;
                var sha256 = new HMACSHA256(encoding.GetBytes(key));
                var hash = sha256.ComputeHash(encoding.GetBytes(value));
                return string.Join("", hash.ToList().Select(t => t.ToString("x2")).ToArray());
            }

            #endregion
        }
    }
}
