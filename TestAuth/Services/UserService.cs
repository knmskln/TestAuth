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
    public async Task<string> BlockUser(BlockUserRequest request){
        var userExists = await _userRepository.CheckIfUserExistsByUserId(request.UserId);
        if (!userExists)
        {
            return "User does not exist.";
        }
        await _userRepository.BlockUser(request.UserId);
        await _userRepository.RemoveRefreshTokens(request.UserId);

        return "User blocked successfully.";
    }
}