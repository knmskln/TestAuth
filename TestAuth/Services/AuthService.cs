using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using TestAuth.Models;
using TestAuth.Payload.Request;
using TestAuth.Payload.Response;
using TestAuth.Repositories;
using JwtRegisteredClaimNames = Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames;

namespace TestAuth.Services;

public class AuthService : IAuthService
{
    private readonly IUserRepository _userRepository;
    private readonly IConfiguration _configuration;

    public AuthService(IConfiguration configuration,
        IUserRepository userRepository)
    {
        _configuration = configuration;
        _userRepository = userRepository;
    }

    public async Task<AuthenticateResponse> Register(RegisterRequest request)
    {
        var user = new User
        {
            Login = request.Login,
            Surname = request.Surname,
            Name = request.Name,
            Patronymic = request.Patronymic,
            Address = request.Address,
            Phone = request.Phone,
            RegistrationDate = DateTime.Now,
            PasswordUpdated = DateTime.Now,
            IsBlocked = false,
            Email = request.Email
        };

        user.Password = HashPassword(request.Password);

        await _userRepository.RegisterUser(user);
        
        return await Login(new AuthenticateRequest { Login = request.Login, Password = request.Password });
    }

    public async Task<AuthenticateResponse> Login(AuthenticateRequest request)
    {
        var user = await _userRepository.GetUserByLogin(request.Login);
        
        if (user.IsBlocked)
        {
            return new AuthenticateResponse(user.Id, user.IsBlocked, null!, null!);
        }
        
        if (user != null)
        {
            var userPermissions = await _userRepository.GetPermissionsForUser(user.Id);

            if (VerifyPassword(request.Password, user.Password))
            {
                var authClaims = new List<Claim>
                {
                    new(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
                    new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                };

                foreach (var permission in userPermissions)
                {
                    authClaims.Add(new Claim("permission", permission.ToString()));
                }

                var token = GetToken(authClaims);
                var refreshToken = GenerateRefreshToken();
                await _userRepository.SaveRefreshTokenToDatabase(user.Id, refreshToken);

                return new AuthenticateResponse(user.Id, user.IsBlocked, new JwtSecurityTokenHandler().WriteToken(token), refreshToken);
            }
        }

        return null;
    }

    public async Task<AuthenticateResponse> RefreshToken(RefreshTokenRequest refreshTokenRequest)
    {
        var isValid = await _userRepository.IsValidRefreshToken(refreshTokenRequest.RefreshToken);
        
        if (isValid)
        {
            var user = await _userRepository.GetUserByRefreshToken(refreshTokenRequest.RefreshToken);
            
            var userPermissions = await _userRepository.GetPermissionsForUser(user.Id);

            var authClaims = new List<Claim>
            {
                new(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
                new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            foreach (var permission in userPermissions)
            {
                authClaims.Add(new Claim("permission", permission.ToString()));
            }

            var newToken = GetToken(authClaims);

            var newRefreshToken = GenerateRefreshToken();
            
            await _userRepository.SaveRefreshTokenToDatabase(user.Id, newRefreshToken);

            await _userRepository.RemoveRefreshTokenFromDatabase(refreshTokenRequest.RefreshToken);

            return new AuthenticateResponse(user.Id, user.IsBlocked,new JwtSecurityTokenHandler().WriteToken(newToken),
                newRefreshToken);
        }

        return null;
    }

    private static string HashPassword(string password)
    {
        return BCrypt.Net.BCrypt.HashPassword(password, BCrypt.Net.BCrypt.GenerateSalt());
    }

    private static bool VerifyPassword(string inputPassword, string hashedPassword)
    {
        return BCrypt.Net.BCrypt.Verify(inputPassword, hashedPassword);
    }
    
    private JwtSecurityToken GetToken(IEnumerable<Claim> authClaims)
    {
        var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));

        var token = new JwtSecurityToken(
            issuer: _configuration["JWT:ValidIssuer"],
            audience: _configuration["JWT:ValidAudience"],
            expires: DateTime.Now.AddMinutes(15),
            claims: authClaims,
            signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256));

        return token;
    }

    private RefreshToken GenerateRefreshToken()
    {
        var refreshToken = new RefreshToken
        {
            Token = Convert.ToHexString(RandomNumberGenerator.GetBytes(64)),
            Expires = DateTime.Now.AddDays(5)
        };

        return refreshToken;
    }
}