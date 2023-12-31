using TestAuth.Entities;

namespace TestAuth.Models;

public class AuthenticateResponse
{
    public int UserId { get; set; }
    public string Token { get; set; }
    public RefreshToken RefreshToken { get; set; }
    
    public AuthenticateResponse(int userId, string token, RefreshToken refreshToken)
    {
        UserId = userId;
        Token = token;
        RefreshToken = refreshToken;
    }
}