using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Http;
using Thinktecture.AuthorizationServer;
using Thinktecture.AuthorizationServer.Interfaces;
using Thinktecture.AuthorizationServer.Models;
using Thinktecture.AuthorizationServer.OAuth2;
using Thinktecture.IdentityModel;

namespace Tests.Token_Controller
{
    [TestClass]
    public class TokenController_Post_ResourceOwnerFlow
    {
        TokenController _TokenController;

        private GlobalConfiguration globalConfiguration;
        private Mock<IResourceOwnerCredentialValidation> rocv;
        private Mock<IAuthorizationServerConfiguration> config;
        private Mock<IStoredGrantManager> handleManager;
        private Mock<IAssertionGrantValidation> assertionGrantValidator;
        private Mock<IClientManager> clientManager;
        private TokenService tokenService;

        private Client _Client;
        private Application _Application;
        private  StoredGrant _StoredGrant;
        private List<Scope> _Scopes;

        [TestInitialize]
        public void Init()
        {
            DataProtectection.Instance = new NoProtection();
            globalConfiguration = new GlobalConfiguration() { Issuer = "Test Issuer" };

            rocv = new Mock<IResourceOwnerCredentialValidation>();
            config = new Mock<IAuthorizationServerConfiguration>();
            handleManager = new Mock<IStoredGrantManager>();
            assertionGrantValidator = new Mock<IAssertionGrantValidation>();
            clientManager = new Mock<IClientManager>();

            tokenService = new TokenService(globalConfiguration);


            #region Setup Test Client
            string secret = "12345678";
            byte[] encodedByte = System.Text.ASCIIEncoding.ASCII.GetBytes(secret);
            string base64EncodedSecret = Convert.ToBase64String(encodedByte);
            _Client = new Client()
            {
                ClientId = "MobileAppShop",
                ClientSecret = base64EncodedSecret,
                Flow = OAuthFlow.ResourceOwner,
                AllowRefreshToken = true
            };
            #endregion

            #region Setup Test Application
            var scope = new Scope();
            scope.Name = "read";
            scope.AllowedClients = new List<Client>();
            scope.AllowedClients.Add(_Client);
            _Scopes = new List<Scope>();
            _Scopes.Add(scope);

            string symmetricKey = "C33333333333333333333333335=";
            byte[] keybytes = Convert.FromBase64String(symmetricKey);
            SecurityKey securityKey = new InMemorySymmetricSecurityKey(keybytes);
            _Application = new Application()
            {
                Name = "Test Application 1",
                Scopes = _Scopes,
                Audience = "Test Audience",
                TokenLifetime = 1,
                AllowRefreshToken = true,
            };
            #endregion

            #region Setup Example StoredGrant
            Claim[] resourceOwnerClaims = { new Claim("Username", "JohnSmith"), new Claim("sub", "JohnSmith") };
            _StoredGrant = new StoredGrant() 
            { 
                GrantId = "MyFavouriteRefrehToken1234",
                CreateRefreshToken = true,
                Client = _Client,
                ResourceOwner = resourceOwnerClaims.ToStoredGrantClaims().ToList(),
                Expiration = DateTime.Now.AddDays(1),
                RefreshTokenExpiration = DateTime.Now.AddMonths(1),
                Type = StoredGrantType.RefreshTokenIdentifier,
                Scopes = _Scopes,
                Application = _Application
            };
            #endregion

            #region Setup Mocking Objects
            // IAuthorizationServerConfiguration
            config.Setup(x => x.FindApplication(It.IsNotNull<string>()))
                .Returns((string name) =>
                {
                    return _Application;
                });
            config.Setup(x => x.GlobalConfiguration).Returns(() => globalConfiguration);

            // IClientManager
            clientManager.Setup(x => x.Get(It.IsNotNull<string>()))
                .Returns((string clientId) =>
                {
                    return _Client;
                });

            // IResourceOwnerCredentialValidation
            rocv.Setup(x => x.Validate(It.IsNotNull<string>(), It.IsNotNull<string>()))
                .Returns((string username, string password) =>
                {
                    return Principal.Create("Test", resourceOwnerClaims);
                });

            // IStoredGrantManager
            handleManager.Setup(x => x.Get(It.IsNotNull<string>()))
                .Returns((string grantIdentifier) => 
                {
                    return _StoredGrant;
                });

            #endregion

            _TokenController = new TokenController(
                rocv.Object,
                config.Object,
                handleManager.Object,
                assertionGrantValidator.Object,
                tokenService,
                clientManager.Object);
            _TokenController.Request = new HttpRequestMessage();
            _TokenController.Request.SetConfiguration(new HttpConfiguration());
        }

        [TestMethod]
        public void Create_Token()
        {
            Claim[] claims = { new Claim("client_id", "MobileAppShop"), new Claim("secret", "12345678") };
            ClaimsPrincipal claimsPrinciple = Principal.Create("Test", claims);

            Thread.CurrentPrincipal = claimsPrinciple;

            TokenRequest tokenRequest = new TokenRequest()
            {
                Grant_Type = "password",
                UserName = "JohnSmith",
                Password = "12345678",
                Scope = "read",
            };

            var response = _TokenController.Post("Test Application 1", tokenRequest);
            TokenResponse tokenResponse;
            response.TryGetContentValue<TokenResponse>(out tokenResponse);

            Assert.IsTrue(response.IsSuccessStatusCode == true);
            Assert.IsFalse(string.IsNullOrEmpty(tokenResponse.AccessToken));
        }

        [TestMethod]
        public void Refresh_Token()
        {
            _StoredGrant.CreateRefreshToken = false;

            Claim[] claims = { new Claim("client_id", "MobileAppShop"), new Claim("secret", "12345678") };
            ClaimsPrincipal claimsPrinciple = Principal.Create("Test", claims);

            Thread.CurrentPrincipal = claimsPrinciple;

            TokenRequest tokenRequest = new TokenRequest()
            {
                Grant_Type = "refresh_token",
                Refresh_Token = "MyFavouriteRefrehToken1234"
            };

            var response = _TokenController.Post("Test Application 1", tokenRequest);
            TokenResponse tokenResponse;
            response.TryGetContentValue<TokenResponse>(out tokenResponse);

            Assert.IsTrue(response.IsSuccessStatusCode == true);
            Assert.IsFalse(string.IsNullOrEmpty(tokenResponse.AccessToken));
        }

        [TestMethod]
        public void Refresh_Token_Create_New()
        {
            Claim[] claims = { new Claim("client_id", "MobileAppShop"), new Claim("secret", "12345678") };
            ClaimsPrincipal claimsPrinciple = Principal.Create("Test", claims);

            Thread.CurrentPrincipal = claimsPrinciple;

            TokenRequest tokenRequest = new TokenRequest()
            {
                Grant_Type = "refresh_token",
                Refresh_Token = "MyFavouriteRefrehToken1234"
            };

            var response = _TokenController.Post("Test Application 1", tokenRequest);
            TokenResponse tokenResponse;
            response.TryGetContentValue<TokenResponse>(out tokenResponse);

            Assert.IsTrue(response.IsSuccessStatusCode == true);
            Assert.IsFalse(string.IsNullOrEmpty(tokenResponse.AccessToken));
        }
    }
}