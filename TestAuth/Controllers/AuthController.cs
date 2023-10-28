using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using TestAuth.Models;
using TestAuth.Services;

namespace TestAuth.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly IAuthService _authenticationService;

    public AuthController(IAuthService authenticationService)
    {
        _authenticationService = authenticationService;
    }

    [AllowAnonymous]
    [HttpPost("login")]
    [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(string))]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> Login([FromBody] AuthenticateRequest request)
    {
        var response = await _authenticationService.Login(request);
        
        if (response == null)
        {
            return BadRequest($"Unable to autenticate user {request.Login}");
        }
        
        return Ok(response);
    }

    [AllowAnonymous]
    [HttpPost("register")]
    [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(string))]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> Register([FromBody] RegisterRequest request)
    {
        var response = await _authenticationService.Register(request);

        return Ok(response);
    }
   
    [AllowAnonymous]
    [HttpPost("refresh-token")]
    [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(AuthenticateResponse))]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequest refreshTokenRequest)
    {
        var response = await _authenticationService.RefreshToken(refreshTokenRequest);

        if (response == null)
        {
            return BadRequest("Refresh Token is revoked or expired");
        }

        return Ok(response);
    }
    
    [AllowAnonymous]
    [HttpPost("revoke-token")]
    [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(AuthenticateResponse))]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public IActionResult RevokeToken([FromBody] RevokeTokenRequest revokeTokenRequest)
    {
        _authenticationService.RevokeToken(revokeTokenRequest);

        if (string.IsNullOrEmpty(revokeTokenRequest.RefreshToken))
            return BadRequest(new { message = "Token is required" });

        return Ok(new { message = "Token revoked" });
    }
}