using Microsoft.AspNetCore.Mvc;
using TestAuth.Entities;

namespace TestAuth.Controllers;

[ApiController]
[Route("[controller]")]
public class AuthController : ControllerBase
{

    private readonly ILogger<AuthController> _logger;

    public AuthController(ILogger<AuthController> logger)
    {
        _logger = logger;
    }

    [HttpGet(Name = "GetUsers")]
    public IEnumerable<User> Get()
    {
        return Enumerable.Range(1, 5).Select(index => new User
            {
                RegistrationDate = DateTime.Now,
            })
            .ToArray();
    }
}