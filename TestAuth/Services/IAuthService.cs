using TestAuth.Payload.Request;
using TestAuth.Payload.Response;

namespace TestAuth.Services;

public interface IAuthService
{
    Task<AuthenticateResponse?> Register(RegisterRequest request);
    Task<AuthenticateResponse?> Login(AuthenticateRequest request);
    Task<AuthenticateResponse?> RefreshToken(string refreshTokenRequest);
}