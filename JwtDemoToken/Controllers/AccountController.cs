using JwtDemoToken.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace JwtDemoToken.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        [HttpPost]
        [Route("Login")]
        [AllowAnonymous]
        public IActionResult Login([FromForm] AuthenticationRequest authenticationRequest)
        {
            var jwtAuthenticationManager = new JwtAuthenticationManager();
            var authResult = jwtAuthenticationManager.Authenticate(authenticationRequest.UserName, authenticationRequest.Password);
            if (authResult == null)
                return Unauthorized();
            else
                return Ok(authResult);
        }
    }
}
