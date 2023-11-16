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

        using var insertUserCommand = new NpgsqlCommand("CALL geolens_registration(@_email, @_login, @_is_blocked, @_address, @_phone, @_patronymic, @_name, @_surname, @_password, @_password_updated, @_registration_date)", connection);
        
        insertUserCommand.Parameters.AddWithValue("_email", user.Email);
        insertUserCommand.Parameters.AddWithValue("_login", user.Login);
        insertUserCommand.Parameters.AddWithValue("_is_blocked", user.IsBlocked);
        insertUserCommand.Parameters.AddWithValue("_address", user.Address ?? string.Empty);
        insertUserCommand.Parameters.AddWithValue("_phone", user.Phone ?? string.Empty);
        insertUserCommand.Parameters.AddWithValue("_patronymic", user.Patronymic ?? string.Empty);
        insertUserCommand.Parameters.AddWithValue("_name", user.Name);
        insertUserCommand.Parameters.AddWithValue("_surname", user.Surname);
        insertUserCommand.Parameters.AddWithValue("_password", user.Password);
        insertUserCommand.Parameters.AddWithValue("_password_updated", user.PasswordUpdated);
        insertUserCommand.Parameters.AddWithValue("_registration_date", user.RegistrationDate);

        await insertUserCommand.ExecuteNonQueryAsync();
    }
    public async Task<User> GetUserByLogin(string identifier)
    {
        using var connection = new NpgsqlConnection(_connectionString);
        await connection.OpenAsync();

        using var command = new NpgsqlCommand("SELECT id, email, login, is_blocked, address, phone, patronymic, name, surname, password, password_updated, registration_date FROM geolens_authentication(@Identifier)", connection);
        command.Parameters.AddWithValue("Identifier", identifier);

        using var reader = await command.ExecuteReaderAsync();
        if (reader.Read())
        {
            var user = new User
            {
                Id = reader.GetInt32(reader.GetOrdinal("id")),
                Email = reader.GetString(reader.GetOrdinal("email")),
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
            await connection.OpenAsync();
            using (var getUserPermissionsCommand = new NpgsqlCommand("SELECT get_user_permissions(@UserId)", connection))
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
    
    public async Task<User> GetUserByRefreshToken(string refreshToken)
    {
        using var connection = new NpgsqlConnection(_connectionString);
        await connection.OpenAsync();

        using var command = new NpgsqlCommand("SELECT id, email, login, is_blocked, address, phone, patronymic, name, surname, password, password_updated, registration_date FROM get_user_by_refresh_token(@RefreshToken)", connection);
        command.Parameters.AddWithValue("RefreshToken", refreshToken);

        using var reader = await command.ExecuteReaderAsync();
        if (reader.Read())
        {
            var user = new User
            {
                Id = reader.GetInt32(reader.GetOrdinal("id")),
                Email = reader.GetString(reader.GetOrdinal("email")),
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
    
    public async Task<bool> IsValidRefreshToken(string refreshToken)
    {
        using var connection = new NpgsqlConnection(_connectionString);
        await connection.OpenAsync();

        using var command = new NpgsqlCommand("SELECT is_valid_refresh_token(@RefreshToken)", connection);
        command.Parameters.AddWithValue("RefreshToken", refreshToken);

        var result = await command.ExecuteScalarAsync();

        return result != null && (bool)result;
    }
    
    public async Task SaveRefreshTokenToDatabase(int userId, RefreshToken refreshToken)
    {
        using var connection = new NpgsqlConnection(_connectionString);
        await connection.OpenAsync();

        using var saveRefreshTokenCommand = new NpgsqlCommand("CALL add_refresh_token(@_user_id, @_refresh_token, @_expires)", connection);

        saveRefreshTokenCommand.Parameters.AddWithValue("_user_id", userId);
        saveRefreshTokenCommand.Parameters.AddWithValue("_refresh_token", refreshToken.Token);
        saveRefreshTokenCommand.Parameters.AddWithValue("_expires", refreshToken.Expires);

        await saveRefreshTokenCommand.ExecuteNonQueryAsync();
    }

    public async Task RemoveRefreshTokenFromDatabase(string oldToken)
    {
        using var connection = new NpgsqlConnection(_connectionString);
        await connection.OpenAsync();

        using var removeRefreshTokenCommand = new NpgsqlCommand("CALL delete_refresh_token(@_refresh_token)", connection);

        removeRefreshTokenCommand.Parameters.AddWithValue("_refresh_token", oldToken);

        await removeRefreshTokenCommand.ExecuteNonQueryAsync();
    }
    public async Task BlockUser(int userId)
    {
        using var connection = new NpgsqlConnection(_connectionString);
        await connection.OpenAsync();

        using var command = new NpgsqlCommand("CALL geolens_block_user(@UserId)", connection);
        command.Parameters.AddWithValue("UserId", userId);

        await command.ExecuteNonQueryAsync();
    }
    
    public async Task RemoveRefreshTokens(int userId)
    {
        using var connection = new NpgsqlConnection(_connectionString);
        using var command = new NpgsqlCommand("DELETE FROM refresh_tokens WHERE user_id = @UserId", connection);
        await connection.OpenAsync();

        command.Parameters.AddWithValue("UserId", userId);

        await command.ExecuteNonQueryAsync();
    }
    public async Task<bool> CheckIfUserExistsByUserId(int userId)
    {
        using var connection = new NpgsqlConnection(_connectionString);
        await connection.OpenAsync();

        using var command = new NpgsqlCommand("SELECT exists_user_by_user_id(@UserId)", connection);
        command.Parameters.AddWithValue("UserId", userId);

        return (bool)await command.ExecuteScalarAsync();
    }
    public async Task<bool> CheckIfUserExistsByLogin(string login)
    {
        using var connection = new NpgsqlConnection(_connectionString);
        await connection.OpenAsync();

        using var checkUserCommand = new NpgsqlCommand("SELECT exists_user_by_login(@Login)", connection);
        checkUserCommand.Parameters.AddWithValue("Login", login);
    
        return (bool)await checkUserCommand.ExecuteScalarAsync();
    }
}
