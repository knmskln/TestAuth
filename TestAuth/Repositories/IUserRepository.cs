using TestAuth.Models;

namespace TestAuth.Repositories;

public interface IUserRepository
{
    Task RegisterUser(User user); 
    Task<User?> GetUserByLogin(string identifier);
    Task<List<int>> GetUserPermissions(int userId);
    Task<User?> GetUserByRefreshToken(string refreshToken);
    Task<bool> IsRefreshTokenValid(string refreshToken);
    Task AddRefreshToken(int userId, RefreshToken refreshToken);
    Task DeleteRefreshTokenByRefreshToken(string oldToken);
    Task UpdateUserDisable(int userId);
    Task DeleteRefreshTokensByUserId(int userId);
    Task<bool> IsUserExistByUserId(int userId);
    Task<bool> IsUserExistByLogin(string login);
}