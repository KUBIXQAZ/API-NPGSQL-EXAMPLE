using API_NPGSQL_EXAMPLE.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.IdentityModel.Tokens;
using Npgsql;
using System.Data;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace API_NPGSQL_EXAMPLE.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : Controller
    {
        private readonly string _connectionString;
        private readonly ILogger<AuthController> _logger;

        private readonly string _jwtKey;
        private readonly string _issuer;
        private readonly string _audience;

        public AuthController(IConfiguration conf, ILogger<AuthController> logger)
        {
            _jwtKey = conf["Jwt:Key"] ?? throw new ArgumentNullException(nameof(_jwtKey));
            _issuer = conf["Jwt:Issuer"] ?? throw new ArgumentNullException(nameof(_issuer));
            _audience = conf["Jwt:Audience"] ?? throw new ArgumentNullException(nameof(_audience));
            _connectionString = conf.GetConnectionString("DefaultConnection") ?? throw new ArgumentNullException(nameof(conf));
            _logger = logger;
        }

        private string GenerateJwtToken(
            string userId,
            string username,
            string email)
        {
            var claims = new[]
                {
                    new Claim(ClaimTypes.NameIdentifier, userId),
                    new Claim(ClaimTypes.Name, username),
                    new Claim(ClaimTypes.Email, email)
                };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtKey));

            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _issuer,
                audience: _audience,
                claims: claims,
                expires: DateTime.UtcNow.AddDays(30),
                signingCredentials: creds
            );

            string jwt = new JwtSecurityTokenHandler().WriteToken(token);

            return jwt;
        }

        [EnableRateLimiting("auth")]
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterRequest request)
        {
            try
            {
                request.Email = request.Email.Trim().ToLower();
                request.Username = request.Username.Trim();

                await using NpgsqlConnection conn = new NpgsqlConnection(_connectionString);
                await conn.OpenAsync();

                var checkQuery = @"
                    SELECT 
                        CASE 
                            WHEN email = @Email THEN 'email'
                            WHEN username = @Username THEN 'username'
                        END as conflict
                    FROM users
                    WHERE email = @Email OR username = @Username
                    LIMIT 1;
                ";
                await using NpgsqlCommand checkCmd = new NpgsqlCommand(checkQuery, conn);
                checkCmd.Parameters.AddWithValue("@Email", request.Email);
                checkCmd.Parameters.AddWithValue("@Username", request.Username);

                var conflict = await checkCmd.ExecuteScalarAsync();

                if (conflict is string conflictType)
                {
                    return Conflict(new
                    {
                        message = conflictType == "email"
                            ? "Email already exists"
                            : "Username already exists"
                    });
                }

                string passwordHash = BCrypt.Net.BCrypt.HashPassword(request.Password);

                string insertQuery = @"
                    INSERT INTO users(
	                email, username, password_hash)
	                VALUES (@Email, @Username, @PasswordHash)
                    RETURNING id;";
                await using NpgsqlCommand insertCmd = new NpgsqlCommand(insertQuery, conn);
                insertCmd.Parameters.AddWithValue("@Email", request.Email);
                insertCmd.Parameters.AddWithValue("@Username", request.Username);
                insertCmd.Parameters.AddWithValue("@PasswordHash", passwordHash);

                var result = await insertCmd.ExecuteScalarAsync();

                if (result == null)
                {
                    _logger.LogError(
                        "User insert failed without exception. Email={Email}, Username={Username}",
                        request.Email,
                        request.Username);

                    return StatusCode(500, "Failed to create user.");
                }

                var userId = Convert.ToInt32(result);

                string jwt = GenerateJwtToken(
                    userId.ToString(),
                    request.Username,
                    request.Email); 

                Response.Cookies.Append("session", jwt, new CookieOptions
                {
                    HttpOnly = true,
                    Secure = true,
                    SameSite = SameSiteMode.Strict,
                    Expires = DateTimeOffset.UtcNow.AddDays(30)
                });

                return Ok(new AuthResponse
                {
                    Id = userId,
                    Email = request.Email,
                    Username = request.Username,
                    Token = jwt
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "User registration failed. Email={Email}, Username={Username}",
                    request.Email,
                    request.Username);
                return Problem("Internal server error.");
            }
        }

        [EnableRateLimiting("auth")]
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            try
            {
                await using NpgsqlConnection conn = new NpgsqlConnection(_connectionString);
                await conn.OpenAsync();

                string selectPasswordQuery = @"
                    SELECT id, username, email, password_hash FROM users
                    WHERE email = @Identifier OR username = @Identifier
                    LIMIT 1;";
                await using NpgsqlCommand cmd = new NpgsqlCommand(selectPasswordQuery, conn);
                cmd.Parameters.AddWithValue("Identifier", request.Identifier);

                await using NpgsqlDataReader reader = await cmd.ExecuteReaderAsync();

                if (!(await reader.ReadAsync()))
                {
                    return Unauthorized(new
                    {
                        message = "Username, email or password is incorrect."
                    });
                }

                int id = reader.GetFieldValue<int>("id");
                string username = reader.GetFieldValue<string>("username");
                string email = reader.GetFieldValue<string>("email");
                string passwordHash = reader.GetFieldValue<string>("password_hash");

                await reader.CloseAsync();

                bool isPasswordCorrect = BCrypt.Net.BCrypt.Verify(request.Password, passwordHash);

                if (!isPasswordCorrect)
                {
                    return Unauthorized(new
                    {
                        message = "Username, email or password is incorrect."
                    });
                }

                string jwt = GenerateJwtToken(
                    id.ToString(),
                    username,
                    email);

                Response.Cookies.Append("session", jwt, new CookieOptions
                {
                    HttpOnly = true,
                    Secure = true,
                    SameSite = SameSiteMode.Strict,
                    Expires = DateTimeOffset.UtcNow.AddDays(30)
                });

                return Ok(new AuthResponse
                {
                    Id = id,
                    Email = email,
                    Username = username,
                    Token = jwt
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Login failed. Identifier={Identifier}",
                    request.Identifier);
                return Problem("Internal server error.");
            }
        }
    }
}
