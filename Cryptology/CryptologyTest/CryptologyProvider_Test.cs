using Cryptology;
using System;
using Xunit;

namespace CryptologyTest
{
    public class CryptologyProvider_Test
    {
        [Theory]
        [InlineData("marsonshine451345")]
        public void Aescrypt_Test(string value)
        {
            var encryptContent = CryptologyProvider.AesCrypt.AesEnCrypt(value,"12345678912345672356412563256478");
            // Ω‚√‹
            var decryptContent = CryptologyProvider.AesCrypt.AesDecrypt(encryptContent, "12345678912345672356412563256478");
            Assert.Equal(value, decryptContent);
        }
    }
}
