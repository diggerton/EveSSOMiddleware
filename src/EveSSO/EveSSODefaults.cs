using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace EveSSO
{
    public static class EveSSODefaults
    {
        public const string AuthenticationScheme = "EveSSO";
        public static readonly string AuthorizationEndpoint = "https://login.eveonline.com/oauth/authorize";
        public static readonly string TokenEndpoint = "https://login.eveonline.com/oauth/token";
        public static readonly string UserInformationEndpoint = "https://login.eveonline.com/oauth/verify";
    }
}
