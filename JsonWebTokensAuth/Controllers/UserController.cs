using firebirdDbFirstAndJWT.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace testTablesWithRoles.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly IUserService _userService;
        public UserController(IUserService userService)
        {
            _userService = userService;
        }
        [HttpPost("Get username"), Authorize]
        public ActionResult<string> GetUsername()
        {
            return Ok(_userService.GetName());
        }
    }
}
