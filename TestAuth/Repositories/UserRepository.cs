using Npgsql;
using TestAuth.Models;

namespace TestAuth.Repositories;

public class UserRepository : IUserRepository
{
    private readonly string _connectionString;

    public UserRepository(IConfiguration configuration)
    {
        _connectionString = configuration.GetConnectionString("db");
    }
    public async Task RegisterUser(User user)
    {
        using var connection = new NpgsqlConnection(_connectionString);
        await connection.OpenAsync();

        using var checkUserCommand = new NpgsqlCommand("SELECT COUNT(*) FROM users WHERE login = @Login", connection);
        checkUserCommand.Parameters.AddWithValue("Login", user.Login);
        var userCount = (long)await checkUserCommand.ExecuteScalarAsync();

        if (userCount > 0)
        {
            throw new ArgumentException($"User with username {user.Login} already exists.");
        }
        
        using var insertUserCommand = new NpgsqlCommand(
            "INSERT INTO users (login, password, surname, name, patronymic, address, phone, registration_date, password_updated, email, is_blocked) " +
            "VALUES (@Login, @PasswordHash, @Surname, @Name, @Patronymic, @Address, @Phone, @RegistrationDate, @PasswordUpdated, @Email, @IsBlocked)",
            connection);

        insertUserCommand.Parameters.AddWithValue("Login", user.Login);
        insertUserCommand.Parameters.AddWithValue("PasswordHash", user.Password);
        insertUserCommand.Parameters.AddWithValue("Surname", user.Surname);
        insertUserCommand.Parameters.AddWithValue("Name", user.Name);
        insertUserCommand.Parameters.AddWithValue("Patronymic", user.Patronymic);
        insertUserCommand.Parameters.AddWithValue("Address", user.Address);
        insertUserCommand.Parameters.AddWithValue("Phone", user.Phone);
        insertUserCommand.Parameters.AddWithValue("RegistrationDate", user.RegistrationDate);
        insertUserCommand.Parameters.AddWithValue("PasswordUpdated", user.PasswordUpdated);
        insertUserCommand.Parameters.AddWithValue("Email", user.Email);
        insertUserCommand.Parameters.AddWithValue("IsBlocked", user.IsBlocked);


        await insertUserCommand.ExecuteNonQueryAsync();
    }
    
    //
    public async Task<User> GetUserByLogin(string identifier)
    {
        using var connection = new NpgsqlConnection(_connectionString);
        await connection.OpenAsync();

        using var command = new NpgsqlCommand("SELECT * FROM geolens_custom_auth(@Identifier)", connection);
        command.Parameters.AddWithValue("Identifier", identifier);

        using var reader = await command.ExecuteReaderAsync();
        if (reader.Read())
        {
            var user = new User
            {
                Id = reader.GetInt32(reader.GetOrdinal("id")),
                Email = reader.IsDBNull(reader.GetOrdinal("email")) ? null : reader.GetString(reader.GetOrdinal("email")),
                Login = reader.GetString(reader.GetOrdinal("login")),
                IsBlocked = reader.GetBoolean(reader.GetOrdinal("is_blocked")),
                Address = reader.IsDBNull(reader.GetOrdinal("address")) ? null : reader.GetString(reader.GetOrdinal("address")),
                Phone = reader.IsDBNull(reader.GetOrdinal("phone")) ? null : reader.GetString(reader.GetOrdinal("phone")),
                Patronymic = reader.IsDBNull(reader.GetOrdinal("patronymic")) ? null : reader.GetString(reader.GetOrdinal("patronymic")),
                Name = reader.GetString(reader.GetOrdinal("name")),
                Surname = reader.GetString(reader.GetOrdinal("surname")),
                Password = reader.GetString(reader.GetOrdinal("password")),
                PasswordUpdated = reader.GetDateTime(reader.GetOrdinal("password_updated")),
                RegistrationDate = reader.GetDateTime(reader.GetOrdinal("registration_date"))
            };

            return user;
        }

        return null;
    }
    
    public async Task<List<int>> GetPermissionsForUser(int userId)
    {
        List<int> permissions = new List<int>();
        using (var connection = new NpgsqlConnection(_connectionString))
        {
            connection.Open();
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
        }
        return permissions;
    }
    
    public bool IsValidRefreshToken(string refreshToken)
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
            if (expires > DateTime.Now)
            {
                return true;
            }
        }

        return false;
    }
    
    public void SaveRefreshTokenToDatabase(int userId, RefreshToken refreshToken)
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

    public void RemoveRefreshTokenFromDatabase(string oldToken)
    {
        using var connection = new NpgsqlConnection(_connectionString);
        connection.Open();

        using var removeRefreshTokenCommand = new NpgsqlCommand(
            "DELETE FROM refresh_tokens WHERE refresh_token = @Token",
            connection);

        removeRefreshTokenCommand.Parameters.AddWithValue("Token", oldToken);

        removeRefreshTokenCommand.ExecuteNonQuery();
    }
    
    public int GetUserIdFromRefreshToken(string refreshToken)
    {
        using var connection = new NpgsqlConnection(_connectionString);
        connection.Open();

        using var getUserIdCommand =
            new NpgsqlCommand("SELECT user_id FROM refresh_tokens WHERE refresh_token = @Token", connection);
        getUserIdCommand.Parameters.AddWithValue("Token", refreshToken);

        var userId = (int)getUserIdCommand.ExecuteScalar();

        return userId;
    }
}
