using TestAuth.Payload;
using TestAuth.Payload.Request;
using TestAuth.Payload.Response;

namespace TestAuth.Services;

public interface IAuthService
{
    Task<AuthenticateResponse> Register(RegisterRequest request);
    Task<AuthenticateResponse> Login(AuthenticateRequest request);
    Task<AuthenticateResponse> RefreshToken(RefreshTokenRequest refreshTokenRequest);
    //void RevokeToken(RevokeTokenRequest revokeTokenRequest);
}