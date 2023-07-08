using firebirdDbFirstAndJWT.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using testTablesWithRoles.Data;

namespace testTablesWithRoles.Services
{
    public class TokenServise : ITokenService
    {
        private readonly ProjectContext _context;
        private readonly IOptions<AuthOptions> _authOptions;
        public TokenServise(ProjectContext context, IOptions<AuthOptions> authOptions)
        {
            _context = context;
            _authOptions = authOptions;
        }
        public string GenerateAccessToken(User user)
        {
            var authParams = _authOptions.Value;

            var userWithRoles = _context.Users.Include(u => u.Roles).FirstOrDefault(u => u.Id == user.Id);

            List<Claim> claims = new List<Claim> {
                new Claim(ClaimTypes.Name, user.Name),

            };
            foreach (var role in userWithRoles.Roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role.UserRole.ToString()));
            }
            var key = authParams.GetSymmetricSecurityKey();
            var creed = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            var token = new JwtSecurityToken(
                authParams.Issuer,
                authParams.Audience,
                claims: claims,
                expires: DateTime.Now.AddSeconds(authParams.TokenLifeTime),
                signingCredentials: creed
                );
            var tokenString = new JwtSecurityTokenHandler().WriteToken(token);
            return tokenString;
        }
        public string GenerateAccessToken(IEnumerable<Claim> claims)
        {
            var authParams = _authOptions.Value;
            var key = authParams.GetSymmetricSecurityKey();
            var creed = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            var token = new JwtSecurityToken(
                authParams.Issuer,
                authParams.Audience,
                claims: claims,
                expires: DateTime.Now.AddSeconds(authParams.TokenLifeTime),
                signingCredentials: creed
                );
            var tokenString = new JwtSecurityTokenHandler().WriteToken(token);
            return tokenString;
        }
        public RefreshToken GenerateRefreshToken()
        {
            var token = new RefreshToken
            {
                Token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)),
                Expires = DateTime.Now.AddDays(7)
            };
            return token;
        }
        public ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
        {
            var authParams = _authOptions.Value;
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = authParams.Issuer,
                ValidateAudience = true,
                ValidAudience = authParams.Audience,
                ValidateLifetime = true,
                IssuerSigningKey = authParams.GetSymmetricSecurityKey(),
                ValidateIssuerSigningKey = true

            };
            var tokenHandler = new JwtSecurityTokenHandler();
            SecurityToken securityToken;
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out securityToken);
            var jwtSecurityToken = securityToken as JwtSecurityToken;
            if (jwtSecurityToken == null || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                throw new SecurityTokenException("Invalid token");
            return principal;
        }
    }
}
