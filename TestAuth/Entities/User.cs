using System.Text.Json.Serialization;

namespace TestAuth.Entities;

public class User
{
    public int Id { get; set; }
    public DateTime RegistrationDate { get; set; }
    public string Login { get; set; }

    [JsonIgnore] public string Password { get; set; }
    
    public DateTime PasswordSettingDate { get; set; }
    public string Surname { get; set; }
    public string Name { get; set; }
    public string Patronymic { get; set; }
    public string Phone { get; set; }
    public string Address { get; set; }

}