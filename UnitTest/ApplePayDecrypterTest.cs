using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Net.BoCheng.Decryption.UnitTest
{
    [TestClass]
    public class ApplePayDecrypterTest
    {
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void InitIncompatibleTest()
        {
            var decrypter = new ApplePayTokenDecrypter();
            decrypter.Init(new AndroidPayParameters());
        }

        [TestMethod]
        public void InitCompatibleTest()
        {
            var decrypter = new ApplePayTokenDecrypter();
            var p = new ApplePayParameters
            {
                //EphemeralPublicKey = "dGVzdA==",
                EphemeralPublicKey = "",
                PrivateKey = "dGVzdA=="
            };
            decrypter.Init(p);

            Assert.AreSame(p, decrypter.PaymentParameters);
        }
    }
}
