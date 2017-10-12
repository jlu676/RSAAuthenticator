using System;
using System.Text;
using System.Security.Cryptography;
using System.IO;
using System.Net.Http;

namespace QuickSecurity.Authenticator
{
    public class GoogleTotp
    {
        private const string _unreservedChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~";
        private readonly int _intervalLength;
        private readonly int _pinCodeLength;
        private readonly int _pinModulo;
        private readonly byte[] _randomBytes = new byte[10];

        public GoogleTotp()
        {
            _pinCodeLength = 6;
            _intervalLength = 30;
            _pinModulo = (int)Math.Pow(10, _pinCodeLength);
            RandomNumberGenerator.Create().GetBytes(_randomBytes);
        }

        public byte[] GetPrivateKey()
        {
            return _randomBytes;
        }

        /// <summary>
        /// Generates a PIN of desired length when given a challenge (counter)
        /// </summary>
        /// <param name="challenge">Counter to calculate hash</param>
        /// <returns>Desired length PIN</returns>
        private string GenerateResponseCode(long challenge, byte[] randomBytes)
        {
            var myHmac = new HMACSHA1(randomBytes);
            myHmac.Initialize();

            var value = BitConverter.GetBytes(challenge);
            Array.Reverse(value); //reverses the challenge array due to differences in c# vs java
            var hash = myHmac.ComputeHash(value);
            var offset = hash[hash.Length - 1] & 0xF;
            var selectedFourBytes = new byte[4];
            //selected bytes are actually reversed due to c# again, thus the weird stuff here
            selectedFourBytes[0] = hash[offset];
            selectedFourBytes[1] = hash[offset + 1];
            selectedFourBytes[2] = hash[offset + 2];
            selectedFourBytes[3] = hash[offset + 3];
            Array.Reverse(selectedFourBytes);
            var finalInt = BitConverter.ToInt32(selectedFourBytes, 0);
            var truncatedHash = finalInt & 0x7FFFFFFF; //remove the most significant bit for interoperability as per HMAC standards
            var pinValue = truncatedHash % _pinModulo; //generate 10^d digits where d is the number of digits
            return PadOutput(pinValue);
        }

        /// <summary>
        /// Gets current interval number since Unix Epoch based on given interval length
        /// </summary>
        /// <returns>Current interval number</returns>
        public long GetCurrentInterval()
        {
            var ts = DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            var currentTimeSeconds = (long)Math.Floor(ts.TotalSeconds);
            return currentTimeSeconds / _intervalLength; // 30 Seconds
        }

        /// <summary>
        /// Pads the output string with leading zeroes just in case the result is less than the length of desired digits
        /// </summary>
        /// <param name="value">Value to pad</param>
        /// <returns>Padded Result</returns>
        private String PadOutput(int value)
        {
            String result = value.ToString();
            for (int i = result.Length; i < _pinCodeLength; i++)
            {
                result = "0" + result;
            }
            return result;
        }

        /// <summary>
        /// This is a different Url Encode implementation since the default .NET one outputs the percent encoding in lower case.
        /// While this is not a problem with the percent encoding spec, it is used in upper case throughout OAuth
        /// </summary>
        /// <param name="value">The value to Url encode</param>
        /// <returns>Returns a Url encoded string</returns>
        protected string UrlEncode(string value)
        {
            var result = new StringBuilder();

            foreach (var symbol in value)
            {
                if (_unreservedChars.IndexOf(symbol) != -1)
                {
                    result.Append(symbol);
                }
                else
                {
                    result.Append($"{(int)symbol:X2}");
                }
            }

            return result.ToString();
        }

        public byte[] GenerateImageByte(int width, int height, string email)
        {
            using (var httpClient = new HttpClient())
            {
                return httpClient.GetByteArrayAsync(GetUrl(width, height, email)).Result;
            }
        }

        public Stream GenerateImageStream(int width, int height, string email)
        {
            using (var httpClient = new HttpClient())
            {
                return  httpClient.GetStreamAsync(GetUrl(width, height,email)).Result;
            }
        }







        private string GetUrl(int width, int height, string email)
        {
            var randomString = CreativeCommons.Transcoder.Base32Encode(_randomBytes);
            var provisionUrl = UrlEncode($"otpauth://totp/{email}?secret={randomString}");
           return  $"http://chart.apis.google.com/chart?cht=qr&chs={width}x{height}&chl={provisionUrl}";
        }
        public string GeneratePin()
        {
            return GenerateResponseCode(GetCurrentInterval(), _randomBytes);
        }
    }
}
