using Microsoft.AspNetCore.Identity;
using System.Security.Principal;
using testTablesWithRoles.Models;

namespace firebirdDbFirstAndJWT.Models
{
    
    public class User
    {
        public int Id { get; set; }
        public string Name { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
        public List<Role> Roles { get; set; } = new();
        public RefreshToken? RefreshToken { get; set; }
    }
}
