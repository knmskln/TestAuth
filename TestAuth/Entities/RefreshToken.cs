namespace TestAuth.Entities;

public class RefreshToken
{
    public int userId { get; set; }
    public string Token { get; set; }
    public DateTime Expires { get; set; }
}