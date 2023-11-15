using System.ComponentModel.DataAnnotations;

namespace TestAuth.Payload.Request;

public class BlockUserRequest
{
    [Required]
    public int UserId { get; set; }
}