using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Net.BoCheng.Decryption
{
    public enum TokenDecrypterType
    {
        Android, Apple
    }

    public static class TokenDecrypterFactory
    {
        public static TokenDecrypter Create(TokenDecrypterType type)
        {
            switch (type)
            {
                case TokenDecrypterType.Android:
                    return new AndroidPayTokenDecrypter();
                case TokenDecrypterType.Apple:
                    return new ApplePayTokenDecrypter();
            }
            throw new NotSupportedException("type not supported.");
        }
    }
}
