using firebirdDbFirstAndJWT.Models;

namespace testTablesWithRoles.Models
{
    public class Role
    {
        public int Id { get; set; }
        public UserRole UserRole { get; set; } = UserRole.User;
        public List<User> Users { get; set; } = new();
        
    }
}
