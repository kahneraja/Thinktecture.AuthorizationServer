using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Thinktecture.AuthorizationServer.Models;
using Thinktecture.AuthorizationServer;
using System.IO;

namespace Tests.Configuration
{
    [TestClass]
    public class WhenCreatingNewOAuthClient
    {
        [TestInitialize]
        public void Init()
        {
            var keyPath = "..\\..\\..\\App_Data\\dataProtectionKeys.json";
            var path = Path.GetFullPath(AppDomain.CurrentDomain.BaseDirectory + keyPath);
            DataProtectection.Instance = new KeyFileProtection(path);
        }

        [TestMethod]
        public void ShouldProvideDeveloperKey()
        {
            var client = CreateMockClient();
            var clientSecret = client.ClientSecret;
            var developerKeyPair = string.Format("{0}:{1}", client.ClientId, client.ClientSecret);
            var bytes = System.Text.Encoding.UTF8.GetBytes(developerKeyPair);
            var developerKey = Convert.ToBase64String(bytes);
        }

        private static Client CreateMockClient()
        {
            var clientId = "JohnSmithMobileDevShop";

            var client = new Client
            {
                Name = "John Smith's Mobile Development Shop",
                ClientId = clientId,
                AuthenticationMethod = ClientAuthenticationMethod.SharedSecret,

                Flow = OAuthFlow.ResourceOwner,
                AllowRefreshToken = false
            };
            client.SetSharedSecret("MyTestSecret");
            return client;
        }
    }
}
