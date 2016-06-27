using System;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Utilities;

namespace Net.BoCheng.Decryption.Parameters
{
    class HkdfParameters : IDerivationParameters
    {
        private HkdfParameters(byte[] ikm, bool skip, byte[] salt, byte[] info)
        {
            if (ikm == null)
            {
                throw new ArgumentNullException("ikm");
            }

            this.Ikm = Arrays.Clone(ikm);
            this.SkipExtract = skip;

            if (salt == null || salt.Length == 0)
            {
                this.Salt = null;
            }
            else
            {
                this.Salt = Arrays.Clone(salt);
            }

            if (info == null)
            {
                this.Info = new byte[0];
            }
            else
            {
                this.Info = Arrays.Clone(info);
            }
        }

        public HkdfParameters(byte[] ikm, byte[] salt, byte[] info)
            : this(ikm, false, salt, info)
        {

        }

        public static HkdfParameters SkipExtractParameters(byte[] ikm, byte[] info)
        {
            return new HkdfParameters(ikm, true, null, info);
        }

        public static HkdfParameters DefaultParameters(byte[] ikm)
        {
            return new HkdfParameters(ikm, false, null, null);
        }

        public byte[] Ikm
        {
            get;
            private set;
        }

        public bool SkipExtract
        {
            get;
            private set;
        }

        public byte[] Salt
        {
            get;
            private set;
        }

        public byte[] Info
        {
            get;
            private set;
        }
    }
}
