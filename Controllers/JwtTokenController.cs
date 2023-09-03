using JwtCookie.API.Backend.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JwtCookie.API.Backend.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class JwtTokenController : ControllerBase
    {
        private const string SecretKey = "you_should_put_your_secret_key_here";
        private readonly SymmetricSecurityKey _securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(SecretKey));

        [HttpPost("login")]
        public IActionResult UserLoginRequest([FromBody] LoginRequest login)
        {
            if (!string.IsNullOrEmpty(login.Username))
            {
                var userIp = HttpContext.Connection.RemoteIpAddress.MapToIPv4().ToString(); // Получение IP-адреса пользователя ::1 (0.0.0.1) == localhost
                var claims = new[]
                {
                    new Claim(ClaimTypes.Name, login.Username),
                    new Claim(ClaimTypes.UserData,userIp)
                };

                var token = new JwtSecurityToken(
                    issuer: "Foitelija",
                    audience: login.Username,
                    claims: claims,
                    expires: DateTime.UtcNow.AddMinutes(10),
                    signingCredentials: new SigningCredentials(_securityKey, SecurityAlgorithms.HmacSha256)
                    );

                var refreshToken = Guid.NewGuid().ToString();

                Response.Cookies.Append("userName", login.Username, new CookieOptions
                {
                    Expires = DateTime.Now.AddDays(30), // Время жизни cookies (например, 30 дней)
                    HttpOnly = true, // Это обеспечивает, что cookies будут доступны только через HTTP (не через JavaScript)
                    SameSite = SameSiteMode.Strict, // Задайте настройки SameSite, чтобы предотвратить CSRF-атаки
                    Secure = true // Установите в true для использования cookies только через HTTPS
                });

                Response.Cookies.Append("refreshToken", refreshToken);

                return Ok(new
                {
                    token = new JwtSecurityTokenHandler().WriteToken(token),
                    refreshToken,
                    IP = User
                });
            }

            return Unauthorized();
        }

        [HttpPost("refresh")]
        public IActionResult RefreshToken()
        {
            var refreshToken = Request.Cookies["refreshToken"];
            var userName = Request.Cookies["userName"];
            if (string.IsNullOrWhiteSpace(refreshToken))
            {
                return BadRequest("Refresh token is missing.");
            }

            var userIp = HttpContext.Connection.RemoteIpAddress.ToString(); // Получение IP-адреса пользователя
            var claims = new[]
            {
                    new Claim(ClaimTypes.Name, userName),
                    new Claim(ClaimTypes.UserData,userIp)
                };

            var token = new JwtSecurityToken(
                issuer: "Foitelija",
                audience: userName,
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(10),
                signingCredentials: new SigningCredentials(_securityKey, SecurityAlgorithms.HmacSha256)
                );
            return Ok(new
            {
                token = new JwtSecurityTokenHandler().WriteToken(token),
                user = userName
            });
        }

    }
}
