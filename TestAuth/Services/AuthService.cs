using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using Npgsql;
using TestAuth.Entities;
using TestAuth.Models;
using JwtRegisteredClaimNames = Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames;

namespace TestAuth.Services;

public class AuthService : IAuthService
{
    private readonly string _connectionString;
    private readonly IConfiguration _configuration;

    public AuthService(IConfiguration configuration)
    {
        _configuration = configuration;
        _connectionString = _configuration.GetConnectionString("db");
    }

    public async Task<AuthenticateResponse> Register(RegisterRequest request)
    {
        using var connection = new NpgsqlConnection(_connectionString);
        await connection.OpenAsync();

        using var checkUserCommand =
            new NpgsqlCommand("SELECT COUNT(*) FROM users WHERE login = @Login", connection);
        checkUserCommand.Parameters.AddWithValue("Login", request.Login);
        var userCount = (long)await checkUserCommand.ExecuteScalarAsync();

        if (userCount > 0)
        {
            throw new ArgumentException($"User with username {request.Login} already exists.");
        }

        var passwordHash = HashPassword(request.Login, request.Password);

        using var insertUserCommand = new NpgsqlCommand(
            "INSERT INTO users (login, password, surname, name, patronymic, address, phone, registration_date, password_updated, email, is_blocked) " +
            "VALUES (@Login, @PasswordHash, @Surname, @Name, @Patronymic, @Address, @Phone, @RegistrationDate, @PasswordUpdated, @Email, @IsBlocked)",
            connection);

        insertUserCommand.Parameters.AddWithValue("Login", request.Login);
        insertUserCommand.Parameters.AddWithValue("PasswordHash", passwordHash);
        insertUserCommand.Parameters.AddWithValue("Surname", request.Surname);
        insertUserCommand.Parameters.AddWithValue("Name", request.Name);
        insertUserCommand.Parameters.AddWithValue("Patronymic", request.Patronymic);
        insertUserCommand.Parameters.AddWithValue("Address", request.Address);
        insertUserCommand.Parameters.AddWithValue("Phone", request.Phone);
        insertUserCommand.Parameters.AddWithValue("RegistrationDate", DateTime.Now);
        insertUserCommand.Parameters.AddWithValue("PasswordUpdated", DateTime.Now);
        insertUserCommand.Parameters.AddWithValue("Email", request.Email);
        insertUserCommand.Parameters.AddWithValue("IsBlocked", false);


        await insertUserCommand.ExecuteNonQueryAsync();

        return await Login(new AuthenticateRequest { Login = request.Login, Password = request.Password });
    }

    public async Task<AuthenticateResponse> Login(AuthenticateRequest request)
    {
        using var connection = new NpgsqlConnection(_connectionString);
        await connection.OpenAsync();

        using var findUserCommand =
            new NpgsqlCommand("SELECT id, password FROM users WHERE login = @Login", connection);
        findUserCommand.Parameters.AddWithValue("Login", request.Login);

        using var reader = await findUserCommand.ExecuteReaderAsync();
        if (reader.Read())
        {
            var userId = reader.GetInt32(0);
            var passwordHash = reader.GetString(1);

            var userPermissions = GetPermissionIdsForUser(userId);

            if (VerifyPassword(request.Login, request.Password, passwordHash))
            {
                var authClaims = new List<Claim>
                {
                    new(JwtRegisteredClaimNames.Sub, userId.ToString()),
                    new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                };

                foreach (var permission in userPermissions)
                {
                    authClaims.Add(new Claim("permission", permission.ToString()));
                }

                var token = GetToken(authClaims);
                var refreshToken = GenerateRefreshToken();
                SaveRefreshTokenToDatabase(userId, refreshToken);
                return new AuthenticateResponse(userId, new JwtSecurityTokenHandler().WriteToken(token), refreshToken);
            }
        }

        return null;
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
            Expires = DateTime.UtcNow.AddDays(7)
        };

        return refreshToken;
    }

    public async Task<AuthenticateResponse> RefreshToken(RefreshTokenRequest refreshTokenRequest)
    {
        var isValid = IsValidRefreshToken(refreshTokenRequest.RefreshToken);

        if (isValid)
        {
            var userId = GetUserIdFromRefreshToken(refreshTokenRequest.RefreshToken);
            var userPermissions = GetPermissionIdsForUser(userId);

            var authClaims = new List<Claim>
            {
                new(JwtRegisteredClaimNames.Sub, userId.ToString()),
                new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            foreach (var permission in userPermissions)
            {
                authClaims.Add(new Claim("permission", permission.ToString()));
            }

            var newToken = GetToken(authClaims);

            var newRefreshToken = GenerateRefreshToken();

            SaveRefreshTokenToDatabase(userId, newRefreshToken);

            RemoveRefreshTokenFromDatabase(refreshTokenRequest.RefreshToken);

            return new AuthenticateResponse(userId, new JwtSecurityTokenHandler().WriteToken(newToken),
                newRefreshToken);
        }

        return null;
    }

    private bool IsValidRefreshToken(string refreshToken)
    {
        using var connection = new NpgsqlConnection(_connectionString);
        connection.Open();

        using var findRefreshTokenCommand =
            new NpgsqlCommand("SELECT expires FROM refresh_tokens WHERE refresh_token = @RefreshToken", connection);
        findRefreshTokenCommand.Parameters.AddWithValue("RefreshToken", refreshToken);

        using var reader = findRefreshTokenCommand.ExecuteReader();
        if (reader.Read())
        {
            var expires = reader.GetDateTime(0);
            if (expires > DateTime.UtcNow)
            {
                return true;
            }
        }

        return false;
    }

    private int GetUserIdFromRefreshToken(string refreshToken)
    {
        using var connection = new NpgsqlConnection(_connectionString);
        connection.Open();

        using var getUserIdCommand =
            new NpgsqlCommand("SELECT user_id FROM refresh_tokens WHERE refresh_token = @Token", connection);
        getUserIdCommand.Parameters.AddWithValue("Token", refreshToken);

        var userId = (int)getUserIdCommand.ExecuteScalar();

        return userId;
    }

    private string HashPassword(string login, string password)
    {
        string combinedString = login + password;

        using (SHA256 sha256 = SHA256.Create())
        {
            byte[] bytes = Encoding.UTF8.GetBytes(combinedString);
            byte[] hashedBytes = sha256.ComputeHash(bytes);
            return BitConverter.ToString(hashedBytes).Replace("-", "").ToLower();
        }
    }

    private bool VerifyPassword(string login, string inputPassword, string hashedPassword)
    {
        var hashedInputPassword = HashPassword(login, inputPassword);
        return string.Equals(hashedInputPassword, hashedPassword, StringComparison.OrdinalIgnoreCase);
    }

    public List<int> GetPermissionIdsForUser(int userId)
    {
        using (var connection = new NpgsqlConnection(_connectionString))
        {
            connection.Open();

            using (var getGroupIdsCommand =
                   new NpgsqlCommand("SELECT group_id FROM user_groups WHERE user_id = @UserId", connection))
            {
                getGroupIdsCommand.Parameters.AddWithValue("UserId", userId);

                List<int> groupIds = new List<int>();
                using (var reader = getGroupIdsCommand.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        int groupId = reader.GetInt32(0);
                        groupIds.Add(groupId);
                    }
                }

                List<int> permissions = new List<int>();
                foreach (var groupId in groupIds)
                {
                    using (var getPermissionsCommand =
                           new NpgsqlCommand("SELECT permission_id FROM group_permissions WHERE group_id = @GroupId",
                               connection))
                    {
                        getPermissionsCommand.Parameters.AddWithValue("GroupId", groupId);

                        using (var reader = getPermissionsCommand.ExecuteReader())
                        {
                            while (reader.Read())
                            {
                                int permissionId = reader.GetInt32(0);
                                permissions.Add(permissionId);
                            }
                        }
                    }
                }

                using (var getUserPermissionsCommand =
                       new NpgsqlCommand("SELECT permission_id FROM user_permissions WHERE user_id = @UserId",
                           connection))
                {
                    getUserPermissionsCommand.Parameters.AddWithValue("UserId", userId);

                    using (var reader = getUserPermissionsCommand.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            int permissionId = reader.GetInt32(0);
                            permissions.Add(permissionId);
                        }
                    }
                }

                return permissions;
            }
        }
    }

    private void SaveRefreshTokenToDatabase(int userId, RefreshToken refreshToken)
    {
        using var connection = new NpgsqlConnection(_connectionString);
        connection.Open();

        using var insertRefreshTokenCommand = new NpgsqlCommand(
            "INSERT INTO refresh_tokens (user_id, refresh_token, expires) VALUES (@UserId, @Token, @Expires)",
            connection);

        insertRefreshTokenCommand.Parameters.AddWithValue("UserId", userId);
        insertRefreshTokenCommand.Parameters.AddWithValue("Token", refreshToken.Token);
        insertRefreshTokenCommand.Parameters.AddWithValue("Expires", refreshToken.Expires);

        insertRefreshTokenCommand.ExecuteNonQuery();
    }

    private void RemoveRefreshTokenFromDatabase(string oldToken)
    {
        using var connection = new NpgsqlConnection(_connectionString);
        connection.Open();

        using var removeRefreshTokenCommand = new NpgsqlCommand(
            "DELETE FROM refresh_tokens WHERE refresh_token = @Token",
            connection);

        removeRefreshTokenCommand.Parameters.AddWithValue("Token", oldToken);

        removeRefreshTokenCommand.ExecuteNonQuery();
    }

    /*public void RevokeToken(RevokeTokenRequest revokeTokenRequest)
    {
        using var connection = new NpgsqlConnection(_connectionString);
        connection.Open();

        using var updateTokenCommand = new NpgsqlCommand(
            "UPDATE refresh_tokens SET revoked = @Revoked WHERE refresh_token = @Token",
            connection);

        updateTokenCommand.Parameters.AddWithValue("Revoked", DateTime.UtcNow);
        updateTokenCommand.Parameters.AddWithValue("Token", revokeTokenRequest.RefreshToken);

        updateTokenCommand.ExecuteNonQuery();    
    }*/
}