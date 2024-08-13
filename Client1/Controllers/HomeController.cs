using Client1.Models;

using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

using System.Diagnostics;

namespace Client1.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;

        public HomeController(ILogger<HomeController> logger)
        {
            _logger = logger;
        }

        public IActionResult Index()
        {
            return View();
        }
        [Authorize]
        public IActionResult Privacy()
        {Console.WriteLine("IN PRIVACY");
            foreach (var claim in User.Claims)
            {
                
                Console.WriteLine($"{claim.Type}: {claim.Value}");
            }
            return View();
        }
        [Authorize(Roles = "Admin")]
        public IActionResult AdminDashboard()
        {
            Console.WriteLine("IN Admin Dashboard");
            foreach (var claim in User.Claims)
            {

                Console.WriteLine($"{claim.Type}: {claim.Value}");
            }
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }

        [HttpGet]
        public IActionResult Logout()
        {
            // Remove JWT token from cookies
            Response.Cookies.Delete("JwtToken");

            // Redirect to the SSO server's logout endpoint with the return URL
            var ssoLogoutUrl = "https://localhost:7025/Identity/Account/Logout";
            var returnUrl = Url.Action("Index", "Home", null, Request.Scheme);
            var logoutUrl = $"{ssoLogoutUrl}?returnUrl={Uri.EscapeDataString(returnUrl)}";

            return Redirect(logoutUrl);
        }
    }
}
