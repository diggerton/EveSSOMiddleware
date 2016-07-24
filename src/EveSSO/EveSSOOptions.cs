using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using EveSSO;
using Microsoft.Extensions.Options;

namespace EveSSO
{
    public class EveSSOOptions : OAuthOptions
    {
        public EveSSOOptions()
        {
            AuthenticationScheme = EveSSODefaults.AuthenticationScheme;
            DisplayName = AuthenticationScheme;
            CallbackPath = new PathString("/signin-evesso");
            AuthorizationEndpoint = EveSSODefaults.AuthorizationEndpoint;
            TokenEndpoint = EveSSODefaults.TokenEndpoint;
            UserInformationEndpoint = EveSSODefaults.UserInformationEndpoint;
        }

        public string AccessType { get; set; }
    }
}
