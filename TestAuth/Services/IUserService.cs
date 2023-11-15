using TestAuth.Payload.Request;

namespace TestAuth.Services;

public interface IUserService
{
    Task<string> BlockUser (BlockUserRequest request);
}