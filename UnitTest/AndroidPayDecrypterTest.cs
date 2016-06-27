using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Net.BoCheng.Decryption.UnitTest
{
    [TestClass]
    public class AndroidPayDecrypterTest
    {
        private string ephemeralPublicKey =
            @"BPhVspn70Zj2Kkgu9t8+ApEuUWsI/zos5whGCQBlgOkuYagOis7qsrcbQrcprjvTZO3XOU+Qbcc28FSgsRtcgQE=";

        private string encryptedMessage = "PHxZxBQvVWwP";
        private string tag = @"TNwa3Q2WiyGi/eDA4XYVklq08KZiSxB7xvRiKK3H7kE=";

        private string privateKey = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgCPSuFr4iSIaQprjj"
                                    + "chHPyDu2NXFe0vDBoTpPkYaK9dehRANCAATnaFz/vQKuO90pxsINyVNWojabHfbx"
                                    + "9qIJ6uD7Q7ZSxmtyo/Ez3/o2kDT8g0pIdyVIYktCsq65VoQIDWSh2Bdm";

        [TestMethod]
        public void DecryptTest()
        {
            var parameter = new AndroidPayParameters
            {
                EphemeralPublicKey = ephemeralPublicKey,
                PrivateKey = privateKey
            };
            var decrypter = new AndroidPayTokenDecrypter();
            decrypter.Init(parameter);
            var decrypted = decrypter.Decrypt(encryptedMessage, tag);

            Assert.AreEqual("plaintext", decrypted);
        }

        [TestMethod]
        [ExpectedException(typeof (ArgumentException))]
        public void InitIncompatibleTest()
        {
            var decrypter = new AndroidPayTokenDecrypter();
            decrypter.Init(new ApplePayParameters());
        }

        [TestMethod]
        public void InitCompatibleTest()
        {
            var decrypter = new AndroidPayTokenDecrypter();
            var p = new AndroidPayParameters
            {
                EphemeralPublicKey = ephemeralPublicKey,
                PrivateKey = privateKey
            };
            decrypter.Init(p);

            Assert.AreSame(p, decrypter.PaymentParameters);
        }
    }
}
