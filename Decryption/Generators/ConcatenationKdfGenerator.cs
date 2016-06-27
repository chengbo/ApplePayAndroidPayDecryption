using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;

namespace Net.BoCheng.Decryption.Generators
{
    /// <summary>
    /// Generator for Concatenation Key Derivation Function defined in NIST SP 800-56A, Sect 5.8.1
    /// </summary>
    public class ConcatenationKdfGenerator : IDerivationFunction
    {
        private byte[] shared;
        private byte[] otherInfo;
        private readonly int hLen;

        public ConcatenationKdfGenerator(IDigest digest)
        {
            Digest = digest;
            hLen = digest.GetDigestSize();
        }

        public IDigest Digest { get; private set; }

        public int GenerateBytes(byte[] output, int outOff, int length)
        {
            if ((output.Length - length) < outOff)
            {
                throw new DataLengthException("output buffer too small");
            }

            byte[] hashBuf = new byte[hLen];
            byte[] c = new byte[4];
            int counter = 1;
            int outputLen = 0;

            Digest.Reset();

            if (length > hLen)
            {
                do
                {
                    ItoOSP(counter, c);

                    Digest.BlockUpdate(c, 0, c.Length);
                    Digest.BlockUpdate(shared, 0, shared.Length);
                    Digest.BlockUpdate(otherInfo, 0, otherInfo.Length);

                    Digest.DoFinal(hashBuf, 0);

                    Array.Copy(hashBuf, 0, output, outOff + outputLen, hLen);
                    outputLen += hLen;
                } while ((counter++) < (length / hLen));
            }

            if (outputLen >= length)
            {
                return length;
            }

            ItoOSP(counter, c);

            Digest.BlockUpdate(c, 0, c.Length);
            Digest.BlockUpdate(shared, 0, shared.Length);
            Digest.BlockUpdate(otherInfo, 0, otherInfo.Length);

            Digest.DoFinal(hashBuf, 0);

            Array.Copy(hashBuf, 0, output, outOff + outputLen, length - outputLen);

            return length;
        }

        public void Init(IDerivationParameters parameters)
        {
            KdfParameters p = parameters as KdfParameters;
            if (p == null)
            {
                throw new ArgumentException("Must be KdfParameters.");
            }

            shared = p.GetSharedSecret();
            otherInfo = p.GetIV();
        }

        private void ItoOSP(int i, byte[] sp)
        {
            sp[0] = (byte)(i >> 24);
            sp[1] = (byte)(i >> 16);
            sp[2] = (byte)(i >> 8);
            sp[3] = (byte)(i >> 0);
        }
    }
}
