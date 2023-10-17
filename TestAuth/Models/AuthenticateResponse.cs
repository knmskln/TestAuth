using TestAuth.Entities;

namespace TestAuth.Models;

public class AuthenticateResponse
{
    public int Id { get; set; }
    public string Name { get; set; }
    public string Surname { get; set; }

    public string Patronymic { get; set; }
    public string Phone { get; set; }
    public string Address { get; set; }
    public string Login { get; set; }
    public string Token { get; set; }


    public DateTime RegistrationDate { get; set; }

    public DateTime PasswordSettingDate { get; set; }

    public AuthenticateResponse(User user, string token)
    {
        Id = user.Id;
        Name = user.Name;
        Surname = user.Surname;
        Login = user.Login;
        Token = token;
    }
}