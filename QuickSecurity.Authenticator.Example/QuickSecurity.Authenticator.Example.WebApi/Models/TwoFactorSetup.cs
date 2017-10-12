using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace QuickSecurity.Authenticator.Example.WebApi.Models
{
    public class TwoFactorSetup
    {
        public string ManualEntryKey { get; internal set; }
        public byte[] QrCodeImage { get; internal set; }
    }
}
