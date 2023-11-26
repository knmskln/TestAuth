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
    public string? Patronymic { get; set; }
    public string? Address { get; set; }
    [Phone]
    public string? Phone { get; set; }
    public RegisterRequest(string login, string email, string password, string surname, string name, string? patronymic, string? address, string? phone)
    {
        Login = login;
        Email = email;
        Password = password;
        Surname = surname;
        Name = name;
        Patronymic = patronymic;
        Address = address;
        Phone = phone;
    }
}