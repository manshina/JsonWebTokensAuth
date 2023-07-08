using System.Security.Claims;

namespace firebirdDbFirstAndJWT.Services
{
    public class UserService : IUserService
    {
        private readonly IHttpContextAccessor _contextAccessor;
        public UserService(IHttpContextAccessor contextAccessor)
        {
            _contextAccessor = contextAccessor;
        }
        public string GetName()
        {
            var result = string.Empty;
            if(_contextAccessor.HttpContext is not null)
            {
                result = _contextAccessor.HttpContext.User?.Identity?.Name;
            }
            return result;
        }
    }
}
