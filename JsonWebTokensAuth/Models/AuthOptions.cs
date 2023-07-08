using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace firebirdDbFirstAndJWT.Models
{
    public class AuthOptions
    {
        public string Issuer { get; set; }
        public string Audience { get; set; }

        public string Secret { get; set; }

        public int TokenLifeTime { get; set; }
        public SymmetricSecurityKey GetSymmetricSecurityKey()
        {
            return new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Secret));
        }
    }
}
