using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using Npgsql;
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

    public async Task<string> Register(RegisterRequest request)
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

        var passwordHash = HashPassword(request.Password);

        using var insertUserCommand = new NpgsqlCommand(
            "INSERT INTO users (login, password, surname, name, patronymic, address, phone, registration_date, password_setting_date, group_id) " +
            "VALUES (@Login, @PasswordHash, @Surname, @Name, @Patronymic, @Address, @Phone, @RegistrationDate, @PasswordSettingDate, @GroupId)",
            connection);

        insertUserCommand.Parameters.AddWithValue("Login", request.Login);
        insertUserCommand.Parameters.AddWithValue("PasswordHash", passwordHash);
        insertUserCommand.Parameters.AddWithValue("Surname", request.Surname);
        insertUserCommand.Parameters.AddWithValue("Name", request.Name);
        insertUserCommand.Parameters.AddWithValue("Patronymic", request.Patronymic);
        insertUserCommand.Parameters.AddWithValue("Address", request.Address);
        insertUserCommand.Parameters.AddWithValue("Phone", request.Phone);
        insertUserCommand.Parameters.AddWithValue("RegistrationDate", DateTime.Now);
        insertUserCommand.Parameters.AddWithValue("PasswordSettingDate", DateTime.Now);
        insertUserCommand.Parameters.AddWithValue("GroupId", 2);

        
        await insertUserCommand.ExecuteNonQueryAsync();

        return await Login(new AuthenticateRequest { Login = request.Login, Password = request.Password });
    }

    public async Task<string> Login(AuthenticateRequest request)
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

            if (VerifyPassword(request.Password, passwordHash))
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
                return new JwtSecurityTokenHandler().WriteToken(token);
            }
        }

        throw new ArgumentException($"Unable to authenticate user {request.Login}");
    }

    private JwtSecurityToken GetToken(IEnumerable<Claim> authClaims)
    {
        var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));

        var token = new JwtSecurityToken(
            issuer: _configuration["JWT:ValidIssuer"],
            audience: _configuration["JWT:ValidAudience"],
            expires: DateTime.Now.AddHours(3),
            claims: authClaims,
            signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256));

        return token;
    }

    private string HashPassword(string password)
    {
        var salt = "SomeRandomSalt";
        var passwordWithSalt = password + salt;
        var sha256 = SHA256.Create();
        var hashedBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(passwordWithSalt));
        return BitConverter.ToString(hashedBytes).Replace("-", "").ToLower();
    }

    private bool VerifyPassword(string inputPassword, string hashedPassword)
    {
        var hashedInputPassword = HashPassword(inputPassword);
        return string.Equals(hashedInputPassword, hashedPassword, StringComparison.OrdinalIgnoreCase);
    }

    public List<int> GetPermissionIdsForUser(int userId)
    {
        using (var connection = new NpgsqlConnection(_connectionString))
        {
            connection.Open();

            using (var getGroupIdCommand =
                   new NpgsqlCommand("SELECT group_id FROM users WHERE id = @UserId", connection))
            {
                getGroupIdCommand.Parameters.AddWithValue("UserId", userId);
                int groupId = (int)getGroupIdCommand.ExecuteScalar();

                using (var getPermissionsCommand =
                       new NpgsqlCommand("SELECT permission_id FROM groups_permissions WHERE group_id = @GroupId",
                           connection))
                {
                    getPermissionsCommand.Parameters.AddWithValue("GroupId", groupId);

                    List<int> permissions = new List<int>();
                    using (var reader = getPermissionsCommand.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            int permissionId = reader.GetInt32(0);
                            permissions.Add(permissionId);
                        }
                    }

                    return permissions;
                }
            }
        }
    }
}