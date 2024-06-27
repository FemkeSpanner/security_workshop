using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using security_workshop.Models;
using System.Diagnostics;
using System.Net;

namespace security_workshop.Controllers
{
    [Authorize]
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;

        public HomeController(ILogger<HomeController> logger)
        {
            _logger = logger;
        }

        public async Task<IActionResult> Index()
        {
            try
            {
                string apiUrl = "https://restcountries.com/v3.1/all";
                string countriesJson = await GetRemoteObjectAsync(apiUrl);

                // Deserialize JSON string to object
                var countries = JsonConvert.DeserializeObject<dynamic>(countriesJson);

                return View(countries);
            }
            catch (Exception ex)
            {
                ViewData["Error"] = $"Error retrieving data: {ex.Message}";
                return View();
            }
        }
        [Authorize(Roles = "Admin")]
        public IActionResult Privacy()
        {
            return View();
        }


        public static async Task<string> GetRemoteObjectAsync(string location)
        {
            using var client = new HttpClient();
            Uri url = new(location);

            if (!url.Host.EndsWith("restcountries.com") ||
                (!url.Scheme.Equals("http") &&
                 !url.Scheme.Equals("https")))
            {
                throw new Exception("Forbidden remote source");
            }

            try
            {
                HttpResponseMessage response = await client.GetAsync(location);
                response.EnsureSuccessStatusCode();
                return await response.Content.ReadAsStringAsync();
            }
            catch (HttpRequestException ex)
            {
                throw new Exception("Error fetching remote object", ex);
            }
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }

    }
}
