using System;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;

namespace Net.BoCheng.Decryption
{
    public abstract class TokenDecrypter
    {
        private readonly byte[] symmetricIv;
        protected byte[] EncryptionKeyBytes;
        protected ECPrivateKeyParameters PrivateKeyParameters;
        protected ECPublicKeyParameters PublicKeyParameters;

        protected byte[] PrivateKeyBytes;
        protected byte[] PublicKeyBytes;

        protected TokenDecrypter()
        {
            symmetricIv = Hex.Decode("00000000000000000000000000000000");
        }

        public string Decrypt(string encryptedMessage, string signature)
        {
            PrivateKeyParameters = CreatePrivateKeyParameters();
            PublicKeyParameters = CreatePublicKeyParameters();

            byte[] sharedSecretBytes = GenerateSharedSecret();
            RestoreSymmertricKey(sharedSecretBytes);

            VerifySignature(encryptedMessage, signature);

            // Decrypting the message.
            var decrypedBytes = DoDecrypt(Base64.Decode(encryptedMessage));

            return Encoding.UTF8.GetString(decrypedBytes);
        }

        public PaymentParameters PaymentParameters
        {
            get; protected set;
        }

        public abstract void Init(PaymentParameters p);

        protected abstract ECPrivateKeyParameters CreatePrivateKeyParameters();

        protected abstract ECPublicKeyParameters CreatePublicKeyParameters();

        protected abstract void RestoreSymmertricKey(byte[] sharedSecretBytes);

        protected abstract void VerifySignature(string encryptedMessage, string signature);

        private byte[] GenerateSharedSecret()
        {
            ECPrivateKeyParameters keyParams = CreatePrivateKeyParameters();
            IBasicAgreement agree = AgreementUtilities.GetBasicAgreement("ECDH");
            agree.Init(keyParams);
            BigInteger sharedSecret = agree.CalculateAgreement(PublicKeyParameters);
            return sharedSecret.ToByteArrayUnsigned();
        }

        private byte[] DoDecrypt(byte[] cipherData)
        {
            byte[] output;
            try
            {
                KeyParameter keyparam = ParameterUtilities.CreateKeyParameter("AES", EncryptionKeyBytes);
                ParametersWithIV parameters = new ParametersWithIV(keyparam, symmetricIv);
                IBufferedCipher cipher = CipherUtilities.GetCipher("AES/CTR/NoPadding");
                cipher.Init(false, parameters);
                try
                {
                    output = cipher.DoFinal(cipherData);
                }
                catch (Exception)
                {
                    throw new ApplicationException("Invalid Data");
                }
            }
            catch (Exception ex)
            {
                throw new ApplicationException("There was an error occured when decrypting message.");
            }

            return output;
        }

        protected static byte[] Combine(byte[] first, byte[] second)
        {
            byte[] ret = new byte[first.Length + second.Length];
            Buffer.BlockCopy(first, 0, ret, 0, first.Length);
            Buffer.BlockCopy(second, 0, ret, first.Length, second.Length);
            return ret;
        }
    }
}
