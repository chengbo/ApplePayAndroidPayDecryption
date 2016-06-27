using System;
using System.Security.Cryptography;
using System.Text;
using Net.BoCheng.Decryption.Generators;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;

namespace Net.BoCheng.Decryption
{
    public class ApplePayParameters : PaymentParameters
    {
        public string MerchantIdentifier { get; set; }
    }

    public class ApplePayTokenDecrypter : TokenDecrypter
    {
        private ApplePayParameters parameters;

        public override void Init(PaymentParameters p)
        {
            parameters = p as ApplePayParameters;
            if (parameters == null)
            {
                throw new ArgumentException("p must be instance of ApplePayParameters.");
            }
            PaymentParameters = parameters;
            PrivateKeyBytes = Base64.Decode(parameters.PrivateKey);
            PublicKeyBytes = Base64.Decode(parameters.EphemeralPublicKey);
        }

        protected override ECPrivateKeyParameters CreatePrivateKeyParameters()
        {
            Asn1Sequence seq = (Asn1Sequence)Asn1Object.FromByteArray(PrivateKeyBytes);
            ECPrivateKeyStructure pKey = ECPrivateKeyStructure.GetInstance(seq);
            AlgorithmIdentifier algId = new AlgorithmIdentifier(X9ObjectIdentifiers.IdECPublicKey, pKey.GetParameters());

            PrivateKeyInfo privInfo = new PrivateKeyInfo(algId, pKey.ToAsn1Object());

            return (ECPrivateKeyParameters)PrivateKeyFactory.CreateKey(privInfo);
        }

        protected override ECPublicKeyParameters CreatePublicKeyParameters()
        {
            return (ECPublicKeyParameters)PublicKeyFactory.CreateKey(PublicKeyBytes);
        }

        protected override void RestoreSymmertricKey(byte[] sharedSecretBytes)
        {
            byte[] merchantIdentifier = GetHashSha256Bytes(parameters.MerchantIdentifier);

            ConcatenationKdfGenerator generator = new ConcatenationKdfGenerator(new Sha256Digest());
            byte[] algorithmIdBytes = Encoding.UTF8.GetBytes((char)0x0d + "id-aes256-GCM");
            byte[] partyUInfoBytes = Encoding.UTF8.GetBytes("Apple");
            byte[] partyVInfoBytes = merchantIdentifier;
            byte[] otherInfoBytes = Combine(Combine(algorithmIdBytes, partyUInfoBytes), partyVInfoBytes);

            generator.Init(new KdfParameters(sharedSecretBytes, otherInfoBytes));
            EncryptionKeyBytes = new byte[32];
            generator.GenerateBytes(EncryptionKeyBytes, 0, EncryptionKeyBytes.Length);
        }

        protected override void VerifySignature(string encryptedMessage, string signature)
        {
            // TODO: implement this
        }

        protected override IBufferedCipher GetCipher()
        {
            return CipherUtilities.GetCipher("AES/GCM/NoPadding");
        }

        private static byte[] GetHashSha256Bytes(string text)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(text);
            SHA256Managed hashstring = new SHA256Managed();
            byte[] hash = hashstring.ComputeHash(bytes);
            return hash;
        }
    }
}
