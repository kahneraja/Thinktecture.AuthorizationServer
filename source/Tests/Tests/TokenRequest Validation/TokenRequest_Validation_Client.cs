﻿using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Security.Claims;
using Thinktecture.AuthorizationServer.Interfaces;
using Thinktecture.AuthorizationServer.Models;
using Thinktecture.AuthorizationServer.OAuth2;
using Thinktecture.IdentityModel;

namespace Thinktecture.AuthorizationServer.Test
{
    [TestClass]
    public class TokenRequest_Validation_Client
    {
        IAuthorizationServerConfiguration _testConfig;
        IStoredGrantManager _storedGrantManager;
        IClientManager _clientManager;
        ClaimsPrincipal _client;

        
        [TestInitialize]
        public void Init()
        {
            DataProtectection.Instance = new NoProtection();

            _testConfig = new TestAuthorizationServerConfiguration();
            _storedGrantManager = new TestTokenHandleManager("abc", "client", "https://validredirect");
            
            _clientManager = new TestClientManager() { Id = "client", Secret = "secret", OAuthFlow = OAuthFlow.Client, AllowRefreshTokens = false };
            _client = Principal.Create("Test", new Claim("client_id", "client"), new Claim("secret", "secret"));
        }

        [TestMethod]
        public void ValidSingleScope()
        {
            var validator = new TokenRequestValidator(_clientManager);
            var app = _testConfig.FindApplication("test");
            var request = new TokenRequest
            {
                Grant_Type = OAuthConstants.GrantTypes.ClientCredentials,
                Scope = "read"
            };

            var result = validator.Validate(app, request, _client);
        }

        [TestMethod]
        public void MissingScope()
        {
            var validator = new TokenRequestValidator(_clientManager);
            var app = _testConfig.FindApplication("test");
            var request = new TokenRequest
            {
                Grant_Type = OAuthConstants.GrantTypes.ClientCredentials,
            };

            try
            {
                var result = validator.Validate(app, request, _client);
            }
            catch (TokenRequestValidationException ex)
            {
                Assert.AreEqual(OAuthConstants.Errors.InvalidScope, ex.OAuthError);
                return;
            }

            Assert.Fail("No exception thrown.");
        }

        [TestMethod]
        public void UnknownScope()
        {
            var validator = new TokenRequestValidator(_clientManager);
            var app = _testConfig.FindApplication("test");
            var request = new TokenRequest
            {
                Grant_Type = OAuthConstants.GrantTypes.ClientCredentials,
                Scope = "unknown"
            };

            try
            {
                var result = validator.Validate(app, request, _client);
            }
            catch (TokenRequestValidationException ex)
            {
                Assert.AreEqual(OAuthConstants.Errors.InvalidScope, ex.OAuthError);
                return;
            }

            Assert.Fail("No exception thrown.");
        }

        [TestMethod]
        public void UnauthorizedScopeSingle()
        {
            var validator = new TokenRequestValidator(_clientManager);
            var app = _testConfig.FindApplication("test");
            var request = new TokenRequest
            {
                Grant_Type = OAuthConstants.GrantTypes.ClientCredentials,
                Scope = "delete"
            };

            try
            {
                var result = validator.Validate(app, request, _client);
            }
            catch (TokenRequestValidationException ex)
            {
                Assert.AreEqual(OAuthConstants.Errors.InvalidScope, ex.OAuthError);
                return;
            }

            Assert.Fail("No exception thrown.");
        }

        [TestMethod]
        public void UnauthorizedScopeMultiple()
        {
            var validator = new TokenRequestValidator(_clientManager);
            var app = _testConfig.FindApplication("test");
            var request = new TokenRequest
            {
                Grant_Type = OAuthConstants.GrantTypes.ClientCredentials,
                Scope = "read delete"
            };

            try
            {
                var result = validator.Validate(app, request, _client);
            }
            catch (TokenRequestValidationException ex)
            {
                Assert.AreEqual(OAuthConstants.Errors.InvalidScope, ex.OAuthError);
                return;
            }

            Assert.Fail("No exception thrown.");
        }

        [TestMethod]
        public void UnauthorizedCodeGrant()
        {
            var validator = new TokenRequestValidator(_storedGrantManager, _clientManager);
            var app = _testConfig.FindApplication("test");
            var request = new TokenRequest
            {
                Grant_Type = OAuthConstants.GrantTypes.AuthorizationCode,
            };

            try
            {
                var result = validator.Validate(app, request, _client);
            }
            catch (TokenRequestValidationException ex)
            {
                Assert.AreEqual(OAuthConstants.Errors.UnauthorizedClient, ex.OAuthError);
                return;
            }

            Assert.Fail("No exception thrown.");
        }

        [TestMethod]
        public void UnauthorizedPasswordGrant()
        {
            var validator = new TokenRequestValidator(_storedGrantManager, _clientManager);
            var app = _testConfig.FindApplication("test");
            var request = new TokenRequest
            {
                Grant_Type = OAuthConstants.GrantTypes.Password,
            };

            try
            {
                var result = validator.Validate(app, request, _client);
            }
            catch (TokenRequestValidationException ex)
            {
                Assert.AreEqual(OAuthConstants.Errors.UnauthorizedClient, ex.OAuthError);
                return;
            }

            Assert.Fail("No exception thrown.");
        }

        [TestMethod]
        public void UnauthorizedRefreshTokenGrant()
        {
            
            var validator = new TokenRequestValidator(_storedGrantManager, _clientManager);
            
            var app = _testConfig.FindApplication("test");
            var request = new TokenRequest
            {
                Grant_Type = OAuthConstants.GrantTypes.RefreshToken
            };

            try
            {
                var result = validator.Validate(app, request, _client);
            }
            catch (TokenRequestValidationException ex)
            {
                Assert.AreEqual(OAuthConstants.Errors.UnauthorizedClient, ex.OAuthError);
                return;
            }

            Assert.Fail("No exception thrown.");
        }
    }
}