using Microsoft.AspNetCore.Mvc;
using TestAuth.Payload.Request;
using TestAuth.Services;

namespace TestAuth.Controllers;

[ApiController]
[Route("api/[controller]")]
public class UserController : ControllerBase
{
    private readonly IUserService _userService;

    public UserController(IUserService userService)
    {
        _userService = userService;
    }
    
    [HttpPost("block-user")]
    [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(string))]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> BlockUser([FromBody] BlockUserRequest request)
    {
        var response = await _userService.BlockUser(request);

        return Ok(response);
    }
}