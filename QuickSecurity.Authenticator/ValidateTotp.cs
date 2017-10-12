using System;
using System.Collections.Generic;
using System.Text;

namespace QuickSecurity.Authenticator
{
    public class ValidateTotp
    {
        public const int DEFAULTDISCREPANCY = 1;

        public bool VerifyCode(string secret, string code)
        {
            return VerifyCode(secret, code, DEFAULTDISCREPANCY);
        }

        public bool VerifyCode(string secret, string code, int discrepancy)
        {
            return VerifyCode(secret, code, discrepancy, this.GetTime());
        }


        public bool VerifyCode(string secret, string code, int discrepancy, long timestamp)
        {
            if (secret == null)
                throw new ArgumentNullException(nameof(secret));
            if (code == null)
                throw new ArgumentNullException(nameof(code));

            // Make sure discrepancy is always positive
            discrepancy = Math.Abs(discrepancy);

            var result = false;

            // To keep safe from timing-attachs we iterate *all* possible codes even though we already may have
            // verified a code is correct.
            for (int i = -discrepancy; i <= discrepancy; i++)
                result |= CodeEquals(this.GetCode(secret, timestamp + (i * this.Period)), code);

            return result;
        }
    }
}
