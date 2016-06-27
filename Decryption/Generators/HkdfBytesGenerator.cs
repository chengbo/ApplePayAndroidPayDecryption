using System;
using Net.BoCheng.Decryption.Parameters;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

namespace Net.BoCheng.Decryption.Generators
{
    class HkdfBytesGenerator : IDerivationFunction
    {
        private readonly HMac hMacHash;
        private readonly int hashLength;

        private byte[] info;
        private byte[] currentT;
        private int generatedBytes;

        public HkdfBytesGenerator(IDigest hash)
        {
            this.hMacHash = new HMac(hash);
            this.hashLength = hash.GetDigestSize();
        }

        public void Init(IDerivationParameters parameters)
        {
            HkdfParameters p = parameters as HkdfParameters;
            if (p == null)
            {
                throw new ArgumentException("Must be HKDFParameters.");
            }

            if (p.SkipExtract)
            {
                hMacHash.Init(new KeyParameter(p.Ikm));
            }
            else
            {
                hMacHash.Init(Extract(p.Salt, p.Ikm));
            }

            info = p.Info;

            generatedBytes = 0;
            currentT = new byte[hashLength];
        }

        private KeyParameter Extract(byte[] salt, byte[] ikm)
        {
            hMacHash.Init(new KeyParameter(ikm));
            if (salt == null)
            {
                hMacHash.Init(new KeyParameter(new byte[hashLength]));
            }
            else
            {
                hMacHash.Init(new KeyParameter(salt));
            }

            hMacHash.BlockUpdate(ikm, 0, ikm.Length);

            byte[] prk = new byte[hashLength];
            hMacHash.DoFinal(prk, 0);
            return new KeyParameter(prk);
        }

        private void ExpandNext()
        {
            int n = generatedBytes / hashLength + 1;
            if (n >= 256)
            {
                throw new DataLengthException("HKDF cannot generate more than 255 blocks of HashLen size");
            }

            if (generatedBytes != 0)
            {
                hMacHash.BlockUpdate(currentT, 0, hashLength);
            }
            hMacHash.BlockUpdate(info, 0, info.Length);
            hMacHash.Update((byte)n);
            hMacHash.DoFinal(currentT, 0);
        }

        public IDigest Digest
        {
            get { return hMacHash.GetUnderlyingDigest(); }
        }

        public int GenerateBytes(byte[] output, int outOff, int length)
        {
            if (generatedBytes + length > 255 * hashLength)
            {
                throw new DataLengthException("HKDF may only be used for 255 * HashLen bytes of output");
            }

            if (generatedBytes % hashLength == 0)
            {
                ExpandNext();
            }

            // copy what is left in the currentT (1..hash
            int toGenerate = length;
            int posInT = generatedBytes % hashLength;
            int leftInT = hashLength - generatedBytes % hashLength;
            int toCopy = Math.Min(leftInT, toGenerate);
            Array.Copy(currentT, posInT, output, outOff, toCopy);
            generatedBytes += toCopy;
            toGenerate -= toCopy;
            outOff += toCopy;

            while (toGenerate > 0)
            {
                ExpandNext();
                toCopy = Math.Min(hashLength, toGenerate);
                Array.Copy(currentT, 0, output, outOff, toCopy);
                generatedBytes += toCopy;
                toGenerate -= toCopy;
                outOff += toCopy;
            }

            return length;
        }
    }
}
