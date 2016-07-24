using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

// For more information on enabling MVC for empty projects, visit http://go.microsoft.com/fwlink/?LinkID=397860

namespace WebTest.Controllers
{
    public class HomeController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }

        [Authorize]
        public IActionResult ProtectedResource()
        {
            var authInfo = HttpContext.Authentication.GetAuthenticateInfoAsync("EveSSO").Result;
            var prop = authInfo.Properties;
            return View();
        }
    }
}
