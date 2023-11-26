using System.ComponentModel.DataAnnotations;

namespace TestAuth.Payload.Request;

public class AuthenticateRequest
{
    [Required]
    public string Login { get; set; }
    
    [Required]
    public string Password { get; set; }
}