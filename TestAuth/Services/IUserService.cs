using Microsoft.AspNetCore.Mvc;
using TestAuth.Payload.Request;

namespace TestAuth.Services;

public interface IUserService
{
    Task<IActionResult> DisableUser (int userId);
}