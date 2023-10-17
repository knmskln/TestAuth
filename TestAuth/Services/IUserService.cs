using TestAuth.Entities;
using TestAuth.Models;

namespace TestAuth.Services;

public interface IUserService
{
    AuthenticateResponse Authenticate(AuthenticateRequest model);
    IEnumerable<User> GetAll();
    User GetById(int id);
}