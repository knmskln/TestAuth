using TestAuth.Models;

namespace TestAuth.Repositories;

public interface IUserRepository
{
    Task RegisterUser(User user); 
    Task<User> GetUserByLogin(string identifier);
    List<int> GetPermissionsForUser(int userId);
    bool IsValidRefreshToken(string refreshToken);
    void SaveRefreshTokenToDatabase(int userId, RefreshToken refreshToken);
    void RemoveRefreshTokenFromDatabase(string oldToken);
    Task<User> GetUserByRefreshToken(string refreshToken);
}