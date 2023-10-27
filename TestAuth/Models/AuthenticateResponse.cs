using TestAuth.Entities;

namespace TestAuth.Models;

public class AuthenticateResponse
{
    public int Id { get; set; }

    public AuthenticateResponse(User user, string token)
    {
        Id = user.Id;
    }
}