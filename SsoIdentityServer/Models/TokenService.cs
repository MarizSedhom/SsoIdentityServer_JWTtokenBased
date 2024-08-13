using Azure;

using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace SsoIdentityServer.Models
{
    namespace SsoIdentityServer.Models
    {
        public class TokenService
        {
            private readonly UserManager<IdentityUser> _userManager;
            private readonly IHttpContextAccessor _httpContextAccessor;

            public TokenService(UserManager<IdentityUser> userManager, IHttpContextAccessor httpContextAccessor)
            {
                _userManager = userManager;
                _httpContextAccessor = httpContextAccessor;
            }


            public async Task<string> GenerateTokenAsync(IdentityUser user)
            {
                var key = Encoding.ASCII.GetBytes("your_32_character_secret_key_here");

                var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(ClaimTypes.NameIdentifier, user.Id)
                };
                // Add role claims
                var roles = await _userManager.GetRolesAsync(user);
                claims.AddRange(roles.Select(role => new Claim(ClaimTypes.Role, role)));

                foreach (var claim in claims)
                {
                    // Check if the claim already exists
                    if (!(await _userManager.GetClaimsAsync(user)).Any(c => c.Type == claim.Type))
                    {
                        await _userManager.AddClaimAsync(user, claim);
                    }
                }

                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = new ClaimsIdentity(claims),
                    Expires = DateTime.UtcNow.AddHours(1),
                    SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature),
                    Issuer = "https://localhost:7025/",
                    Audience = "api1"
                };

                var tokenHandler = new JwtSecurityTokenHandler();
                var token = tokenHandler.CreateToken(tokenDescriptor);
                var tokenString = tokenHandler.WriteToken(token);
                // Store the token in a cookie using IHttpContextAccessor
                var cookieOptions = new CookieOptions
                {
                    HttpOnly = true,
                    Secure = true,
                    SameSite = SameSiteMode.Strict
                };

                _httpContextAccessor.HttpContext.Response.Cookies.Append("JwtToken", tokenString, cookieOptions);

                return tokenString;
            }
        }
    }


}
