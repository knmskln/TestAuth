using Microsoft.AspNetCore.Mvc;
using TestAuth.Payload.Request;
using TestAuth.Repositories;

namespace TestAuth.Services;

public class UserService : IUserService
{
    private readonly IUserRepository _userRepository;

    public UserService(IUserRepository userRepository)
    {
        _userRepository = userRepository;
    }
    public async Task<IActionResult> DisableUser(int userId){
        var userExists = await _userRepository.IsUserExistByUserId(userId);
        if (!userExists)
        {
            return new NotFoundResult();
        }
        await _userRepository.UpdateUserDisable(userId);
        await _userRepository.DeleteRefreshTokensByUserId(userId);

        return new OkResult();
    }
}