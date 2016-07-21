using System;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Options;

namespace UsingGoogleOAuthAsTemplate
{
    public static class EveSSOAppBuilderExtension
    {
        public static IApplicationBuilder UseEveSSOAuthentication(this IApplicationBuilder app)
        {
            if (app == null)
                throw new ArgumentNullException(nameof(app));

            return app.UseMiddleware<EveSSOMiddleware>();
        }

        public static IApplicationBuilder UseEveSSOAuthentication(this IApplicationBuilder app, EveSSOOptions options)
        {
            if (app == null)
                throw new ArgumentNullException(nameof(app));

            if (options == null)
                throw new ArgumentNullException(nameof(options));

            return app.UseMiddleware<EveSSOMiddleware>(Options.Create(options));
        }
    }
}
