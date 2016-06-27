using System;
using System.Security.Cryptography;
using System.Text;
using Net.BoCheng.Decryption.Generators;
using Net.BoCheng.Decryption.Parameters;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;

namespace Net.BoCheng.Decryption
{
    public class AndroidPayParameters : PaymentParameters
    {
        
    }

    public class AndroidPayTokenDecrypter : TokenDecrypter
    {
        private readonly byte[] hkdfSalt;
        private readonly byte[] hkdfInfo;
        private byte[] macKey;

        public AndroidPayTokenDecrypter()
        {
            // equivalent to a zeroed salt of hashLen
            hkdfSalt = null;
            hkdfInfo = Encoding.UTF8.GetBytes("Android");
        }

        public override void Init(PaymentParameters p)
        {
            var parameters = p as AndroidPayParameters;
            if (parameters == null)
            {
                throw new ArgumentException("p must be instance of AndroidPayParameters.");
            }
            PaymentParameters = parameters;
            PrivateKeyBytes = Base64.Decode(parameters.PrivateKey);
            PublicKeyBytes = Base64.Decode(parameters.EphemeralPublicKey);
        }

        protected override ECPrivateKeyParameters CreatePrivateKeyParameters()
        {
            return (ECPrivateKeyParameters) PrivateKeyFactory.CreateKey(PrivateKeyBytes);
        }

        protected override ECPublicKeyParameters CreatePublicKeyParameters()
        {
            X9ECParameters ecP = NistNamedCurves.GetByName("P-256");
            var parameters = new ECDomainParameters(ecP.Curve, ecP.G, ecP.N, ecP.H, ecP.GetSeed());
            return new ECPublicKeyParameters(parameters.Curve.DecodePoint(PublicKeyBytes),
                parameters);
        }

        protected override void RestoreSymmertricKey(byte[] sharedSecretBytes)
        {
            // Deriving encryption and mac keys.
            HkdfBytesGenerator hkdfBytesGenerator = new HkdfBytesGenerator(new Sha256Digest());
            byte[] khdfInput = Combine(PublicKeyBytes, sharedSecretBytes);
            hkdfBytesGenerator.Init(new HkdfParameters(khdfInput, hkdfSalt, hkdfInfo));
            EncryptionKeyBytes = new byte[16];
            hkdfBytesGenerator.GenerateBytes(EncryptionKeyBytes, 0, 16);
            macKey = new byte[16];
            hkdfBytesGenerator.GenerateBytes(macKey, 0, 16);
        }

        protected override void VerifySignature(string encryptedMessage, string signature)
        {
            // Verifying Message Authentication Code (aka mac/tag)
            HMACSHA256 hmac = new HMACSHA256(macKey);
            byte[] encryptedMessageBytes = Base64.Decode(encryptedMessage);
            byte[] expectedTag = hmac.ComputeHash(encryptedMessageBytes);
            byte[] tagBytes = Convert.FromBase64String(signature);

            if (!IsTagMatched(tagBytes, expectedTag))
            {
                throw new ApplicationException("Bad Message Authentication Code!");
            }
        }

        protected override IBufferedCipher GetCipher()
        {
            return CipherUtilities.GetCipher("AES/CTR/NoPadding");
        }

        private static bool IsTagMatched(byte[] a, byte[] b)
        {
            if (a.Length != b.Length)
            {
                return false;
            }

            int result = 0;
            for (int i = 0; i < a.Length; i++)
            {
                result |= a[i] ^ b[i];
            }

            return result == 0;
        }
    }
}
