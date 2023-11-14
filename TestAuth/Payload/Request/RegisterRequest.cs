using System.ComponentModel.DataAnnotations;

namespace TestAuth.Payload.Request;

public class RegisterRequest
{
    [Required]
    public string Login { get; set; }
    [Required]
    [EmailAddress]
    public string Email { get; set; }
    [Required]
    public string Password { get; set; }
    [Required]
    public string Surname { get; set; }
    [Required]
    public string Name { get; set; }
    public string Patronymic { get; set; }   
    [Required]
    public string Address { get; set; }
    [Required]
    [Phone]
    public string Phone { get; set; }
}