using System.ComponentModel.DataAnnotations;

namespace API_NPGSQL_EXAMPLE.Models
{
    public class LoginRequest
    {
        [Required] public string Identifier { get; set; } = string.Empty;
        [Required] public string Password { get; set; } = string.Empty;
    }
}