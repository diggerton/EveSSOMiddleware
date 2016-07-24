using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http.Authentication;

// For more information on enabling MVC for empty projects, visit http://go.microsoft.com/fwlink/?LinkID=397860

namespace WebTest.Controllers
{
    public class AuthController : Controller
    {
        [HttpGet]
        [AllowAnonymous]
        public async Task EveSSOLogin(string returnUrl = null, string newScopes = null)
        {
            var redirectUrl = Url.Action("ExternalLoginCallback", "Auth", new { ReturnUrl = returnUrl });
            var authProperties = new AuthenticationProperties { RedirectUri = redirectUrl };
            
            // Pass space separated string of scopes to AuthenticationProperties.Items dictionary with key of 'scopes' to
            //   add additional scopes to this request.
            // string newScopesString = "fleetWrite fleetRead";
            // authProperties.Items["scopes"] = newScopesString;
            
            await HttpContext.Authentication.ChallengeAsync("EveSSO", authProperties);
        }

        [HttpGet]
        [Authorize]
        public IActionResult ExternalLoginCallback(string returnUrl = null)
        {
            if (!string.IsNullOrWhiteSpace(returnUrl) && Url.IsLocalUrl(returnUrl))
                return Redirect(returnUrl);
            else
                return RedirectToAction("Index", "Home");
        }

        [HttpGet]
        [Authorize]
        public async Task<IActionResult> EveSSOLogout()
        {
            await HttpContext.Authentication.SignOutAsync("Cookies");
            return RedirectToAction("Index", "Home");
        }

    }
}
