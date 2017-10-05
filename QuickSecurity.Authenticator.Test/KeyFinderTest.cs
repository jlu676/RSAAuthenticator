﻿using System;
using Xunit;
using Xunit.Sdk;

namespace QuickSecurity.Authenticator.Test
{
    public class KeyFinderTest
    {
        public static DateTime _epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        [Fact]
        public void FindIterationNumber()
        {
            var secretKey = "PJWUMZKAUUFQKJBAMD6VGJ6RULFVW4ZH";
            var targetCode = "267762";

            var tfa = new TwoFactorAuthenticator();
            var mins = DateTime.UtcNow.Subtract(_epoch).TotalMinutes;

            long currentTime = 1416643820;

            for (long i = currentTime; i >= 0; i=i-60)
            {
                var result = tfa.GeneratePINAtInterval(secretKey, i, 6);
                if (result == targetCode)
                {
                    Assert.True(true);
                }
            }

            Assert.True(false);
        }
    }
}
