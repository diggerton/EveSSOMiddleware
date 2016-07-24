using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using EveSSO;
using Microsoft.AspNetCore.Authentication.Cookies;
using System.Threading.Tasks;
using System.Net.Http;
using System;
using Microsoft.AspNetCore.Authentication;
using System.Linq;
using System.Globalization;
using Microsoft.AspNet.Http.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using System.Collections.Generic;

namespace WebTest
{
    public class Startup
    {
        public Startup(IHostingEnvironment env)
        {
            var builder = new ConfigurationBuilder()
                .SetBasePath(env.ContentRootPath)
                .AddUserSecrets()
                .AddJsonFile("appsettings.json", optional: true, reloadOnChange: true)
                .AddJsonFile($"appsettings.{env.EnvironmentName}.json", optional: true)
                .AddEnvironmentVariables();

            Configuration = builder.Build();
        }

        public IConfigurationRoot Configuration { get; set; }

        // This method gets called by the runtime. Use this method to add services to the container.
        // For more information on how to configure your application, visit http://go.microsoft.com/fwlink/?LinkID=398940
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddAuthentication();
            services.AddMvc();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerFactory)
        {
            loggerFactory.AddConsole(Configuration.GetSection("Logging"));
            loggerFactory.AddDebug();

            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseBrowserLink();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
            }

            app.UseStaticFiles();

            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationScheme = CookieAuthenticationDefaults.AuthenticationScheme,
                LoginPath = new PathString("/Auth/EveSSOLogin"),
                AutomaticChallenge = true,
                SlidingExpiration =false,

                Events = new CookieAuthenticationEvents
                {
                    OnValidatePrincipal = EveSSOClientValidator.ValidateAsync
                }
            });
            app.UseEveSSOAuthentication(GetEveSSOOptions());

            app.UseMvcWithDefaultRoute();
        }

        private EveSSOOptions GetEveSSOOptions()
        {
            var options = new EveSSOOptions
            {
                ClientId = Configuration["EveSSO:ClientId"],
                ClientSecret = Configuration["EveSSO:ClientSecret"],
                SaveTokens = true,
                SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme,

                Events = new OAuthEvents
                {
                    OnRedirectToAuthorizationEndpoint = EveSSOClientValidator.OAuthRedirectInterceptor
                }
            };

            // Add custom base scopes that will always be in the challenge URL
            //options.Scope.Add("fleetRead");

            options.Scope.Add("publicData");

            return options;
        }

        public static class EveSSOClientValidator
        {
            public static async Task ValidateAsync(CookieValidatePrincipalContext context)
            {
                DateTime expires = DateTime.MinValue;

                var tokens = context.Properties.GetTokens();
                var accessToken = tokens.FirstOrDefault(t => t.Name.Equals("access_token", StringComparison.OrdinalIgnoreCase))?.Value;
                var expiresString = tokens.FirstOrDefault(t => t.Name.Equals("expires_at", StringComparison.OrdinalIgnoreCase))?.Value;

                if (string.IsNullOrWhiteSpace(expiresString) || 
                    !DateTime.TryParse(expiresString, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out expires) ||
                    DateTime.UtcNow > expires.ToUniversalTime())
                {
                    context.RejectPrincipal();
                    await context.HttpContext.Authentication.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                }
            }

            public static async Task OAuthRedirectInterceptor(OAuthRedirectToAuthorizationContext context)
            {
                await Task.FromResult(0);
            }
        }
    }
}
