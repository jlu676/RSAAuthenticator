using System.IO;
using Xunit;

namespace QuickSecurity.Authenticator.Test
{
    public class SetupTest
    {
        [Fact]
        public void TestSetup()
        {
            var key = "";
            var issuer = "Test Two Factor";
            var email= "user@example.com";
            var twoFactorAuthenticator = new GoogleTotp();
            var imageStream = twoFactorAuthenticator.GenerateImage(300, 300, email);

            using (var fileStream = new FileStream(@"C:\test.jpg",FileMode.Create))
            {
                imageStream.CopyTo(fileStream);
            }


           var pin = twoFactorAuthenticator.GeneratePin();
        }




    }
}
