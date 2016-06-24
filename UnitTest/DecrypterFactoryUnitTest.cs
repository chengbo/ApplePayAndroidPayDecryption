using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Net.BoCheng.Decryption.UnitTest
{
    [TestClass]
    public class DecrypterFactoryUnitTest
    {
        [TestMethod]
        public void CreateUnitTest()
        {
            Assert.IsInstanceOfType(TokenDecrypterFactory.Create(TokenDecrypterType.Android), typeof(AndroidPayTokenDecrypter));
            Assert.IsInstanceOfType(TokenDecrypterFactory.Create(TokenDecrypterType.Apple), typeof(ApplePayTokenDecrypter));
        }
    }
}
