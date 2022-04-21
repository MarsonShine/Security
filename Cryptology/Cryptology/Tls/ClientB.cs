using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Cryptology.Tls
{
    public class ClientB
    {
        public byte[] bobPublicKey;
        private byte[] bobKey;
        public ClientB()
        {
            using ECDiffieHellmanCng bob = new ECDiffieHellmanCng();

            bob.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
            bob.HashAlgorithm = CngAlgorithm.Sha256;
            bobPublicKey = bob.PublicKey.ToByteArray();
            bobKey = bob.DeriveKeyMaterial(CngKey.Import(ClientA.publicKey, CngKeyBlobFormat.EccPublicBlob));
        }

        public void Receive(byte[] encryptedMessage, byte[] iv)
        {

            using Aes aes = new AesCryptoServiceProvider();
            aes.Key = bobKey;
            aes.IV = iv;
            // Decrypt the message
            using MemoryStream plaintext = new MemoryStream();
            using CryptoStream cs = new CryptoStream(plaintext, aes.CreateDecryptor(), CryptoStreamMode.Write);
            cs.Write(encryptedMessage, 0, encryptedMessage.Length);
            cs.Close();
            string message = Encoding.UTF8.GetString(plaintext.ToArray());
            Console.WriteLine(message);
        }
    }
}
