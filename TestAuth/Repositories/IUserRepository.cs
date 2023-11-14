using TestAuth.Models;

namespace TestAuth.Repositories;

public interface IUserRepository
{
    Task RegisterUser(User user); 
    Task<User> GetUserByLogin(string identifier);
    Task<List<int>> GetPermissionsForUser(int userId);
}