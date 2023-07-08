namespace firebirdDbFirstAndJWT.Models
{
    public class RefreshToken
    {
        public int id { get ; set; }
        public string Token { get; set; }  = string.Empty;
        public DateTime Created { get; set; } = DateTime.Now;
        public DateTime Expires { get; set; } = DateTime.Now;
        public int UserId { get; set; }
        public User? User { get; set; }
    }
}
