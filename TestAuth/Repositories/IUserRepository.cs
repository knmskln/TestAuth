using TestAuth.Models;

namespace TestAuth.Repositories;

public interface IUserRepository
{
    Task RegisterUser(User user); 
    Task<User> GetUserByLogin(string identifier);
    Task<List<int>> GetPermissionsForUser(int userId);
    Task<bool> IsValidRefreshToken(string refreshToken);
    Task SaveRefreshTokenToDatabase(int userId, RefreshToken refreshToken);
    Task RemoveRefreshTokenFromDatabase(string oldToken);
    Task<User> GetUserByRefreshToken(string refreshToken);
}