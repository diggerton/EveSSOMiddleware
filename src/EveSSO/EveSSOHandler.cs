using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http.Authentication;
using System.Net.Http.Headers;
using Newtonsoft.Json.Linq;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Http.Features.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Authentication.OAuth;
using System.Globalization;
using Microsoft.Extensions.Primitives;
using System.Text;
using System.Linq;


namespace EveSSO
{
    internal class EveSSOHandler : OAuthHandler<EveSSOOptions>
    {
        public EveSSOHandler(HttpClient httpClient)
            : base(httpClient)
        { }

        protected override string BuildChallengeUrl(AuthenticationProperties properties, string redirectUri)
        {
            var defaultScopes = new List<string>(Options.Scope);
            string newScopesString;
            var newScopes = properties.Items.TryGetValue("scopes", out newScopesString);
            var scope = FormatScope(defaultScopes, newScopesString?.Split(' '));

            var state = Options.StateDataFormat.Protect(properties);

            var queryBuilder = new QueryBuilder()
            {
                { "client_id", Options.ClientId },
                { "scope", scope },
                { "response_type", "code" },
                { "redirect_uri", redirectUri },
                { "state", state },
            };

            return Options.AuthorizationEndpoint + queryBuilder.ToString();
        }
        public HttpRequestMessage BuildRefreshRequestMessage(string refreshToken)
        {
            var queryBuilder = new QueryBuilder()
            {
                { "grant_type", "refresh_token" },
                { "refresh_token",  refreshToken }
            };
            var requestContent = new FormUrlEncodedContent(queryBuilder);

            var requestMessage = new HttpRequestMessage(HttpMethod.Post, Options.TokenEndpoint);
            requestMessage.Headers.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"{ Options.ClientId }:{ Options.ClientSecret }")));
            requestMessage.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            requestMessage.Content = requestContent;

            return requestMessage;
        }

        public string FormatScope(IEnumerable<string> scopes, string[] newScopes = null)
        {
            var fullScopesList = new List<string>(scopes);
            if(newScopes != null)
            {
                foreach (var s in newScopes)
                    fullScopesList.Add(s);
            }

            return string.Join(" ", fullScopesList);
        }

        protected override async Task<AuthenticationTicket> CreateTicketAsync(ClaimsIdentity identity, AuthenticationProperties properties, OAuthTokenResponse tokens)
        {
            var request = new HttpRequestMessage(HttpMethod.Get, Options.UserInformationEndpoint);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", tokens.AccessToken);

            var response = await Backchannel.SendAsync(request, Context.RequestAborted);
            response.EnsureSuccessStatusCode();

            var verifyResponsePayload = JObject.Parse(await response.Content.ReadAsStringAsync());

            var ticket = new AuthenticationTicket(new ClaimsPrincipal(identity), properties, Options.AuthenticationScheme);
            var context = new OAuthCreatingTicketContext(ticket, Context, Options, Backchannel, tokens, verifyResponsePayload);

            /* Sample verifyResponsePayload
             * {
                    "CharacterID": 273042051,
                    "CharacterName": "CCP illurkall",
                    "ExpiresOn": "2014-05-23T15:01:15.182864Z",
                    "Scopes": " ",
                    "TokenType": "Character",
                    "CharacterOwnerHash": "XM4D...FoY="
                }
             */

            var characterId = verifyResponsePayload.Value<int>("CharacterID");
            var characterName = verifyResponsePayload.Value<string>("CharacterName");
            var expiresOn = verifyResponsePayload.Value<DateTime>("ExpiresOn");
            var tokenType = verifyResponsePayload.Value<string>("TokenType");
            var characterOwnerHash = verifyResponsePayload.Value<string>("CharacterOwnerHash");
            var scopes = verifyResponsePayload.Value<string>("Scopes");

            var claimsList = new List<Claim>();
            claimsList.Add(new Claim(ClaimTypes.Name, characterName, ClaimValueTypes.String, Options.ClaimsIssuer));
            claimsList.Add(new Claim("evesso:characterId", characterId.ToString(), ClaimValueTypes.Integer, Options.ClaimsIssuer));
            claimsList.Add(new Claim("evesso:expiresOn", expiresOn.ToString(), ClaimValueTypes.DateTime, Options.ClaimsIssuer));
            claimsList.Add(new Claim("evesso:characterOwnerHash", characterOwnerHash, ClaimValueTypes.String, Options.ClaimsIssuer));
            if(!string.IsNullOrWhiteSpace(scopes))
            {
                foreach (var scope in scopes.Split(' '))
                    claimsList.Add(new Claim("evesso:scope", scope, ClaimValueTypes.String, Options.ClaimsIssuer));
            }
            
            context.Identity.AddClaims(claimsList);
            ticket.Properties.ExpiresUtc = expiresOn;
            
            await Options.Events.CreatingTicket(context);

            return context.Ticket;
        }

        protected override async Task<AuthenticateResult> HandleRemoteAuthenticateAsync()
        {
            AuthenticationProperties properties = null;
            var query = Request.Query;

            var error = query["error"];
            if (!StringValues.IsNullOrEmpty(error))
            {
                var failureMessage = new StringBuilder();
                failureMessage.Append(error);
                var errorDescription = query["error_description"];
                if (!StringValues.IsNullOrEmpty(errorDescription))
                {
                    failureMessage.Append(";Description=").Append(errorDescription);
                }
                var errorUri = query["error_uri"];
                if (!StringValues.IsNullOrEmpty(errorUri))
                {
                    failureMessage.Append(";Uri=").Append(errorUri);
                }

                return AuthenticateResult.Fail(failureMessage.ToString());
            }

            var code = query["code"];
            var state = query["state"];

            properties = Options.StateDataFormat.Unprotect(state);
            
            if (properties == null)
            {
                return AuthenticateResult.Fail("The oauth state was missing or invalid.");
            }

            // OAuth2 10.12 CSRF
            if (!ValidateCorrelationId(properties))
            {
                return AuthenticateResult.Fail("Correlation failed.");
            }

            if (StringValues.IsNullOrEmpty(code))
            {
                return AuthenticateResult.Fail("Code was not found.");
            }
           
            var tokens = await ExchangeCodeAsync(code, BuildRedirectUri(Options.CallbackPath));

            if (tokens.Error != null)
            {
                return AuthenticateResult.Fail(tokens.Error);
            }

            if (string.IsNullOrEmpty(tokens.AccessToken))
            {
                return AuthenticateResult.Fail("Failed to retrieve access token.");
            }

            var identity = new ClaimsIdentity(Options.ClaimsIssuer);

            if (Options.SaveTokens)
            {
                var authTokens = new List<AuthenticationToken>();

                authTokens.Add(new AuthenticationToken { Name = "access_token", Value = tokens.AccessToken });
                if (!string.IsNullOrEmpty(tokens.RefreshToken))
                {
                    authTokens.Add(new AuthenticationToken { Name = "refresh_token", Value = tokens.RefreshToken });
                }

                if (!string.IsNullOrEmpty(tokens.TokenType))
                {
                    authTokens.Add(new AuthenticationToken { Name = "token_type", Value = tokens.TokenType });
                }

                if (!string.IsNullOrEmpty(tokens.ExpiresIn))
                {
                    int value;
                    if (int.TryParse(tokens.ExpiresIn, NumberStyles.Integer, CultureInfo.InvariantCulture, out value))
                    {
                        // https://www.w3.org/TR/xmlschema-2/#dateTime
                        // https://msdn.microsoft.com/en-us/library/az4se3k1(v=vs.110).aspx
                        var expiresAt = Options.SystemClock.UtcNow + TimeSpan.FromSeconds(value);
                        authTokens.Add(new AuthenticationToken
                        {
                            Name = "expires_at",
                            Value = expiresAt.ToString("o", CultureInfo.InvariantCulture)
                        });
                    }
                }

                properties.StoreTokens(authTokens);
            }

            return AuthenticateResult.Success(await CreateTicketAsync(identity, properties, tokens));
        }
    }

}
