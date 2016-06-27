using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto.Parameters;

namespace Net.BoCheng.Decryption
{
    public class ApplePayParameters : PaymentParameters
    {

    }

    public class ApplePayTokenDecrypter : TokenDecrypter
    {
        public override void Init(PaymentParameters p)
        {
            throw new NotImplementedException();
        }

        protected override ECPrivateKeyParameters CreatePrivateKeyParameters()
        {
            throw new NotImplementedException();
        }

        protected override ECPublicKeyParameters CreatePublicKeyParameters()
        {
            throw new NotImplementedException();
        }

        protected override void RestoreSymmertricKey(byte[] sharedSecretBytes)
        {
            throw new NotImplementedException();
        }

        protected override void VerifySignature(string encryptedMessage, string signature)
        {
            throw new NotImplementedException();
        }
    }
}
