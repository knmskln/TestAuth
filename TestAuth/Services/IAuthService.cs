using TestAuth.Entities;
using TestAuth.Models;

namespace TestAuth.Services;

public interface IAuthService
{
    Task<string> Register(RegisterRequest request);
    Task<string> Login(AuthenticateRequest request);
}