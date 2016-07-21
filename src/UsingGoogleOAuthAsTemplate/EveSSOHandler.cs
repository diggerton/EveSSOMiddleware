using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Http.Authentication;
using System.Net.Http.Headers;
using Newtonsoft.Json.Linq;
using Microsoft.AspNetCore.Http.Extensions;

namespace UsingGoogleOAuthAsTemplate
{
    internal class EveSSOHandler : OAuthHandler<EveSSOOptions>
    {
        public EveSSOHandler(HttpClient httpClient)
            : base(httpClient)
        { }

        protected async override Task<AuthenticationTicket> CreateTicketAsync(ClaimsIdentity identity, AuthenticationProperties properties, OAuthTokenResponse tokens)
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
            claimsList.Add(new Claim(ClaimTypes.PrimarySid, characterId.ToString(), ClaimValueTypes.Integer, Options.ClaimsIssuer));
            claimsList.Add(new Claim(ClaimTypes.Name, characterName, ClaimValueTypes.String, Options.ClaimsIssuer));
            claimsList.Add(new Claim(ClaimTypes.NameIdentifier, characterName, ClaimValueTypes.String, Options.ClaimsIssuer));
            claimsList.Add(new Claim(ClaimTypes.Expiration, expiresOn.ToString(), ClaimValueTypes.DateTime, Options.ClaimsIssuer));
            claimsList.Add(new Claim(ClaimTypes.Hash, characterOwnerHash, ClaimValueTypes.String, Options.ClaimsIssuer));
            if(!string.IsNullOrWhiteSpace(scopes))
            {
                foreach (var scope in scopes.Split(' '))
                    claimsList.Add(new Claim("urn:evesso:scope", scope, ClaimValueTypes.String, Options.ClaimsIssuer));
            }

            context.Identity.AddClaims(claimsList);

            await Options.Events.CreatingTicket(context);

            return context.Ticket;
        }
        
    }

}
