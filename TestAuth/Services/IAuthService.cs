using TestAuth.Models;

namespace TestAuth.Services;

public interface IAuthService
{
    Task<AuthenticateResponse> Register(RegisterRequest request);
    Task<AuthenticateResponse> Login(AuthenticateRequest request);
    Task<AuthenticateResponse> RefreshToken(RefreshTokenRequest refreshTokenRequest);

}