using firebirdDbFirstAndJWT.Models;
using Microsoft.EntityFrameworkCore;
using testTablesWithRoles.Models;

namespace testTablesWithRoles.Data
{
    public class ProjectContext : DbContext
    {
        public ProjectContext(DbContextOptions<ProjectContext> options) : base(options)
        {

        }

        public DbSet<User> Users { get; set; } 
        public DbSet<Role> Roles { get; set; }
        public DbSet<RefreshToken> RefreshTokens { get; set; }
    }
}
