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
            "INSERT INTO users (id, login, password_hash, surname, name, patronymic, address, phone, registration_date, password_setting_date) " +
            "VALUES (@Id, @Login, @PasswordHash, @Surname, @Name, @Patronymic, @Address, @Phone, @RegistrationDate, @PasswordSettingDate)",
            connection);

        var userId = Guid.NewGuid();
        insertUserCommand.Parameters.AddWithValue("Id", userId);
        insertUserCommand.Parameters.AddWithValue("Login", request.Login);
        insertUserCommand.Parameters.AddWithValue("PasswordHash", passwordHash);
        insertUserCommand.Parameters.AddWithValue("Surname", request.Surname);
        insertUserCommand.Parameters.AddWithValue("Name", request.Name);
        insertUserCommand.Parameters.AddWithValue("Patronymic", request.Patronymic);
        insertUserCommand.Parameters.AddWithValue("Address", request.Address);
        insertUserCommand.Parameters.AddWithValue("Phone", request.Phone);
        insertUserCommand.Parameters.AddWithValue("RegistrationDate", DateTime.Now);
        insertUserCommand.Parameters.AddWithValue("PasswordSettingDate", DateTime.Now);

        await insertUserCommand.ExecuteNonQueryAsync();

        return await Login(new AuthenticateRequest { Login = request.Login, Password = request.Password });
    }

    public async Task<string> Login(AuthenticateRequest request)
    {
        using var connection = new NpgsqlConnection(_connectionString);
        await connection.OpenAsync();

        using var findUserCommand =
            new NpgsqlCommand("SELECT id, login, password_hash FROM users WHERE login = @Login", connection);
        findUserCommand.Parameters.AddWithValue("Login", request.Login);

        using var reader = await findUserCommand.ExecuteReaderAsync();
        if (reader.Read())
        {
            var userId = reader.GetGuid(0);
            var login = reader.GetString(1);
            var passwordHash = reader.GetString(2);
            
            var userPermissions = GetPermissionIdsForUser(userId);

            if (VerifyPassword(request.Password, passwordHash))
            {
                var authClaims = new List<Claim>
                {
                    new(JwtRegisteredClaimNames.Sub, userId.ToString()),
                    new(JwtRegisteredClaimNames.Exp, $"{new DateTimeOffset(DateTime.Now.AddHours(3)).ToUnixTimeSeconds()}"),
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
    
    public List<int> GetPermissionIdsForUser(Guid userId)
    {
        List<int> permissionIds = new List<int>();

        using (var connection = new NpgsqlConnection(_connectionString))
        {
            connection.Open();

            string sql = "SELECT permissionid FROM userpermissions WHERE userid = @Id;";

            using (var command = new NpgsqlCommand(sql, connection))
            {
                command.Parameters.AddWithValue("Id", userId);

                using (var reader = command.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        int permissionId = reader.GetInt32(0);
                        permissionIds.Add(permissionId);
                        Console.WriteLine(permissionIds);
                    }
                }
            }
        }

        return permissionIds;
    }

}