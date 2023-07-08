using Azure.Core;
using firebirdDbFirstAndJWT.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Swashbuckle.AspNetCore.SwaggerGen;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using testTablesWithRoles.Data;
using testTablesWithRoles.Models;
using testTablesWithRoles.Services;

namespace firebirdDbFirstAndJWT.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        
        private readonly IConfiguration _configuration;
        private readonly IOptions<AuthOptions> _authOptions;
        private readonly ProjectContext _context;
        private readonly ITokenService _tokenService;
        public AuthController(IConfiguration configuration, IOptions<AuthOptions> authOptions, ProjectContext context, ITokenService tokenService)
        {
            _configuration = configuration;
            _authOptions = authOptions;
            _context = context;
            _tokenService = tokenService;
        }
        
        //[HttpPost("register")]
        //public ActionResult<User> Register(string username, string password)
        ////{
            ////user.Name = username;
            ////user.Password = password;
            
            ////return Ok(user);
        ////}
        [HttpPost("Get username"), Authorize]
        public ActionResult<string> GetUsername()
        {
            string? username = User?.Identity?.Name;
            var userRolesClainms = User?.FindAll(ClaimTypes.Role);
            var userRoles = userRolesClainms?.Select(c => c.Value).ToList();
            return Ok(new {username , userRoles });
        }
        [HttpPost("login")]
        public ActionResult<User> Login(UserDto userDto)
        {
            var user = Authorize(userDto.Name, userDto.Password);
            if (user != null)
            {
                var token = _tokenService.GenerateAccessToken(user);
                var refreshToken = _tokenService.GenerateRefreshToken();
                SetRefreshToken(refreshToken);
                user.RefreshToken = refreshToken;
                _context.SaveChanges();
                return Ok(new
                {
                    token = token,
                    refresh = refreshToken
                });
            }
            return Unauthorized();

        }
        //TO DO: revoke token
        [HttpPost("refresh-token")]
        public ActionResult<string> RefreshToken(AuthenticatedResponse tokens)
        {
            string accessToken = tokens.AccessToken;
            string refreshToken = tokens.RefreshToken;
            if (tokens.AccessToken is null)
            {
                return BadRequest("no access token procided");
            }
            if( string.IsNullOrWhiteSpace(tokens.RefreshToken))
            {
                refreshToken = Request.Cookies["refreshToken"];
            }
            

            var principal = _tokenService.GetPrincipalFromExpiredToken(accessToken);
            var username = principal.Identity?.Name; //this is mapped to the Name claim by default
            var user = _context.Users.Include(u=>u.RefreshToken).FirstOrDefault(u=>u.Name == username);
            if (user is null || user.RefreshToken?.Token != refreshToken || user.RefreshToken.Expires <= DateTime.Now)
                return BadRequest("Invalid client request");
            var newAccessToken = _tokenService.GenerateAccessToken(principal.Claims);
            var newRefreshToken = _tokenService.GenerateRefreshToken();
            SetRefreshToken(newRefreshToken);

            user.RefreshToken = newRefreshToken;
            _context.SaveChanges();
            return Ok(new AuthenticatedResponse()
            {
                AccessToken = newAccessToken,
                RefreshToken = newRefreshToken.Token
            });

        }
        private User? Authorize(string email, string password)
        {
            var user = _context.Users.Include(u=>u.RefreshToken).FirstOrDefault(c => c.Name == email && c.Password == password);
            return user;
        }       
        
        private void SetRefreshToken(RefreshToken newRefreshToken)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Expires = newRefreshToken.Expires
            };
            Response.Cookies.Append("refreshToken", newRefreshToken.Token, cookieOptions);
        }
    }
}
