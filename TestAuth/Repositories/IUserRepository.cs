using TestAuth.Models;

namespace TestAuth.Repositories;

public interface IUserRepository
{
    Task RegisterUser(User user); 
    Task<User> GetUserByLogin(string identifier);
    Task<List<int>> GetPermissionsForUser(int userId);
    Task<User> GetUserByRefreshToken(string refreshToken);
    Task<bool> IsValidRefreshToken(string refreshToken);
    Task SaveRefreshTokenToDatabase(int userId, RefreshToken refreshToken);
    Task RemoveRefreshTokenFromDatabase(string oldToken);
    Task BlockUser(int userId);
    Task RemoveRefreshTokens(int userId);
    Task<bool> CheckIfUserExistsByUserId(int userId);
    Task<bool> CheckIfUserExistsByLogin(string login);
}