using API_NPGSQL_EXAMPLE.Models;
using Microsoft.AspNetCore.Mvc;

namespace API_NPGSQL_EXAMPLE.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : Controller
    {
        private readonly string _connectionString;

        public AuthController(IConfiguration conf)
        {
            _connectionString = conf.GetConnectionString("DefaultConnection") ?? throw new ArgumentNullException(nameof(conf));
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterRequest request)
        {

        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {

        }
    }
}
