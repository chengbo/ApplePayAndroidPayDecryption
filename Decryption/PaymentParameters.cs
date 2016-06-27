using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Net.BoCheng.Decryption
{
    public abstract class PaymentParameters
    {
        public string EphemeralPublicKey { get; set; }

        public string PrivateKey { get; set; }
    }
}
