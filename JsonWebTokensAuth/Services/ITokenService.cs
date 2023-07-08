using firebirdDbFirstAndJWT.Models;
using System.Security.Claims;

namespace testTablesWithRoles.Services
{
    public interface ITokenService
    {
        string GenerateAccessToken(User user);
        string GenerateAccessToken(IEnumerable<Claim> claims);
        RefreshToken GenerateRefreshToken();
        ClaimsPrincipal GetPrincipalFromExpiredToken(string token);
    }
}
