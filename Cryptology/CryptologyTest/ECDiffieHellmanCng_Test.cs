using Cryptology.Tls;
using System;
using System.Collections.Generic;
using System.Text;
using Xunit;

namespace CryptologyTest
{
    public class ECDiffieHellmanCng_Test
    {
        [Fact]
        public void ECDH_Test()
        {
            ClientA.Start();
            Assert.True(true);
        }
    }
}
