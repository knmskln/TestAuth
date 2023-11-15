using TestAuth.Models;

namespace TestAuth.Payload.Response;

public class AuthenticateResponse
{
    //мб всего юзера
    public int UserId { get; set; }
    public bool IsBlocked { get; set; }
    public string Token { get; set; }
    public RefreshToken RefreshToken { get; set; }
    
    public AuthenticateResponse(int userId, bool isBlocked, string token, RefreshToken refreshToken)
    {
        UserId = userId;
        IsBlocked = isBlocked;
        Token = token;
        RefreshToken = refreshToken;
    }

}