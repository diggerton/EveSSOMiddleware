using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Http;
using System;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Logging;
using System.Text.Encodings.Web;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Authentication;

namespace EveSSO
{
    public class EveSSOMiddleware : OAuthMiddleware<EveSSOOptions>
    {
        public EveSSOMiddleware(
            RequestDelegate next, 
            IDataProtectionProvider dataProtectionProvider, 
            ILoggerFactory loggerFactory, 
            UrlEncoder encoder, 
            IOptions<SharedAuthenticationOptions> sharedOptions, 
            IOptions<EveSSOOptions> options)
            :base(next, dataProtectionProvider, loggerFactory, encoder, sharedOptions, options)
        {
            if (next == null)
                throw new ArgumentNullException(nameof(next));

            if (dataProtectionProvider == null)
                throw new ArgumentNullException(nameof(dataProtectionProvider));

            if (loggerFactory == null)
                throw new ArgumentNullException(nameof(loggerFactory));

            if (encoder == null)
                throw new ArgumentNullException(nameof(encoder));

            if (sharedOptions == null)
                throw new ArgumentNullException(nameof(sharedOptions));

            if (options == null)
                throw new ArgumentNullException(nameof(options));
        }

        protected override AuthenticationHandler<EveSSOOptions> CreateHandler()
        {
            return new EveSSOHandler(Backchannel);
        }
    }
}
