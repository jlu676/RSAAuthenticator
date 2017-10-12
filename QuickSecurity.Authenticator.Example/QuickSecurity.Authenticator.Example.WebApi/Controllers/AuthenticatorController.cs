using System.IO;
using Microsoft.AspNetCore.Mvc;
using QuickSecurity.Authenticator.Example.WebApi.Models;

namespace QuickSecurity.Authenticator.Example.WebApi.Controllers
{
    [Route("api/[controller]")]
    public class AuthenticatorController : Controller
    {
        [HttpGet("/Validate")]
        public TwoFactorSetup GetSetupInfo(string emailAddress)
        {
            var twoFactorAuthenticator = new GoogleTotp();
            var imageStream = new MemoryStream(twoFactorAuthenticator.GenerateImage(300, 300, emailAddress));


            imageStream.ToArray();


            var pin = twoFactorAuthenticator.GeneratePin();





            //var twoFactorAuthenticator = new TwoFactorAuthenticator();
            //var setupInfo = twoFactorAuthenticator.GenerateSetupCode("Test Two Factor", "user@example.com", key, 300, 300);
            return null;
        }

        // GET api/values/5
        [HttpGet("{id}")]
        public string Get(int id)
        {
            return "value";
        }

        // POST api/values
        [HttpPost]
        public void Post([FromBody]string value)
        {
        }

        // PUT api/values/5
        [HttpPut("{id}")]
        public void Put(int id, [FromBody]string value)
        {
        }

        // DELETE api/values/5
        [HttpDelete("{id}")]
        public void Delete(int id)
        {
        }
    }
}
