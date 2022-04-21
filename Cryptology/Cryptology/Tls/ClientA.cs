using System.IO;
using System.Security.Cryptography;
using System.Text;

/// <summary>
/// ECDH 密钥交换过程
/// A 和 B 创建一个密钥组成密钥对，这是用于后续的 Diffie-Hellman 密钥交换操作
/// A 和 B 使用双方同意的参数配置KDF。
/// A 把公钥发给 B
/// B 把公钥发给 A
/// A 和 B 使用彼此的公钥生成密钥协议，并将KDF应用到密钥协议以生成密钥。
/// 注意：KDF是用于生成一个随机数的，HMAC-based Extract-and-Expand Key Derivation Function
/// </summary>
namespace Cryptology.Tls
{
    public class ClientA
    {
        public static byte[] publicKey;

        public static void Start()
        {
            using var alice = new ECDiffieHellmanCng();
            alice.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
            alice.HashAlgorithm = CngAlgorithm.Sha256;
            publicKey = alice.PublicKey.ToByteArray();
            var bob = new ClientB();
            // 生成key
            var bobKey = CngKey.Import(bob.bobPublicKey, CngKeyBlobFormat.EccPublicBlob);
            // 利用两方的公钥生成一个密钥协议
            var clientAKey = alice.DeriveKeyMaterial(bobKey);
            byte[] encryptedMessage = null;
            byte[] iv = null;
            // 将生成的密钥用于后续的连接加密
            Send(clientAKey, "被加密的消息内容", out encryptedMessage, out iv);
            bob.Receive(encryptedMessage, iv);
        }

        private static void Send(byte[] key, string secretMessage, out byte[] encryptedMessage, out byte[] iv)
        {
            using Aes aes = new AesCryptoServiceProvider();
            aes.Key = key;
            iv = aes.IV;

            // Encrypt the message
            using MemoryStream ciphertext = new MemoryStream();
            using CryptoStream cs = new CryptoStream(ciphertext, aes.CreateEncryptor(), CryptoStreamMode.Write);
            byte[] plaintextMessage = Encoding.UTF8.GetBytes(secretMessage);
            cs.Write(plaintextMessage, 0, plaintextMessage.Length);
            cs.Close();
            encryptedMessage = ciphertext.ToArray();
        }
    }
}
