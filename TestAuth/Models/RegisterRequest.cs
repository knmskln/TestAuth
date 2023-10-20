using System.ComponentModel.DataAnnotations;

namespace TestAuth.Models;

public class RegisterRequest
{
    [Required]
    public string Login { get; set; }
    [Required]
    public string Password { get; set; }
    [Required]
    public string Surname { get; set; }
    [Required]
    public string Name { get; set; }
    [Required]
    public string Patronymic { get; set; }   
    [Required]
    public string Address { get; set; }
    [Required]
    public string Phone { get; set; }
}