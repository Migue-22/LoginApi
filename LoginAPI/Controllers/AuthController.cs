using LoginAPI.Services.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Web;

namespace LoginAPI.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly UserManager<IdentityUser> _userManager;
    private readonly SignInManager<IdentityUser> _signInManager;
    private readonly IConfiguration _configuration;
    private readonly IMyEmailSender _emailSender;

    public AuthController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager, IConfiguration configuration, IMyEmailSender emailSender)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _configuration = configuration;
        _emailSender = emailSender;
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterDto dto)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        var userExists = await _userManager.FindByNameAsync(dto.Username);
        if (userExists != null)
            return BadRequest(new { Message = "User already exists" });

        var user = new IdentityUser { UserName = dto.Username, Email = dto.Email };

        var result = await _userManager.CreateAsync(user, dto.Password);
        if (!result.Succeeded)
            return BadRequest(result.Errors);

        var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
        var encodedToken = HttpUtility.UrlEncode(token);

        var confirmationLink = $"https://localhost:7017/api/Auth/confirm-email?userId={user.Id}&token={encodedToken}";

        await _emailSender.SendEmailAsync(user.Email, "Confirma tu correo",
            $"Por favor confirma tu cuenta dando click aquí: <a href='{confirmationLink}'>Confirmar correo</a>");

        return Ok(new { Message = "Usuario creado. Se envió un correo de confirmación." });
    }


    [HttpGet("confirm-email")]
    public async Task<IActionResult> ConfirmEmail([FromQuery] string userId, [FromQuery] string token)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null) return NotFound("Usuario no encontrado");

        var result = await _userManager.ConfirmEmailAsync(user, token);
        return result.Succeeded ? Ok("Correo confirmado correctamente") : BadRequest("Error al confirmar correo");

    }


    public class ConfirmEmailDto
    {
        public string UserId { get; set; }
        public string Token { get; set; }
    }

    [Authorize]
    [HttpPost("update-profile")]
    public async Task<IActionResult> UpdateProfile([FromBody] UpdateProfileDto dto)
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null) return Unauthorized();

        user.Email = dto.Email;
        user.UserName = dto.Username;
        var result = await _userManager.UpdateAsync(user);

        return result.Succeeded ? Ok("Perfil actualizado.") : BadRequest(result.Errors);
    }

    public class UpdateProfileDto
    {
        [Required]
        public string Username { get; set; }
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }


    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginDto dto)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var user = await _userManager.FindByNameAsync(dto.Username);
        if (user == null)
        {
            return Unauthorized(new { Message = "Credenciales inválidas." });
        }
        if (!await _userManager.IsEmailConfirmedAsync(user))
        {
            return Unauthorized(new { Message = "Email no confirmado." });
        }

        var result = await _signInManager.PasswordSignInAsync(user, dto.Password, false, false);
        if (!result.Succeeded)
        {
            return Unauthorized(new { Message = "Credenciales inválidas." });
        }

        var token = await GenerateJwtToken(user);
        return Ok(new { Token = token });
    }

    private async Task<string> GenerateJwtToken(IdentityUser user)
    {
        var roles = await _userManager.GetRolesAsync(user);

        var claims = new List<Claim>
    {
        new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
        new Claim(ClaimTypes.NameIdentifier, user.Id),
        new Claim(ClaimTypes.Email, user.Email)
    };

        claims.AddRange(roles.Select(role => new Claim(ClaimTypes.Role, role)));

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            issuer: _configuration["Jwt:Issuer"],
            audience: _configuration["Jwt:Audience"],
            claims: claims,
            expires: DateTime.Now.AddHours(1),
            signingCredentials: creds
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    [Authorize]
    [HttpPost("change-password")]
    public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordDto dto)
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null) return Unauthorized();

        var result = await _userManager.ChangePasswordAsync(user, dto.CurrentPassword, dto.NewPassword);
        return result.Succeeded ? Ok("Password changed.") : BadRequest(result.Errors);
    }

    public class ChangePasswordDto
    {
        public string CurrentPassword { get; set; }
        public string NewPassword { get; set; }
    }

    [HttpPost("forgot-password")]
    public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordDto dto)
    {
        var user = await _userManager.FindByEmailAsync(dto.Email);
        if (user == null) return NotFound("Email not found");

        var token = await _userManager.GeneratePasswordResetTokenAsync(user);
        // En un sistema real, deberías enviar este token por correo
        return Ok(new { ResetToken = token });
    }

    [HttpPost("reset-password")]
    public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordDto dto)
    {
        var user = await _userManager.FindByEmailAsync(dto.Email);
        if (user == null) return NotFound("User not found");

        var result = await _userManager.ResetPasswordAsync(user, dto.Token, dto.NewPassword);
        return result.Succeeded ? Ok("Password reset.") : BadRequest(result.Errors);
    }

    public class ForgotPasswordDto { public string Email { get; set; } }
    public class ResetPasswordDto
    {
        public string Email { get; set; }
        public string Token { get; set; }
        public string NewPassword { get; set; }
    }



    [HttpGet("profile")]
    [Authorize]
    public IActionResult Profile()
    {
        var username = User.Identity?.Name;
        var roles = User.Claims
            .Where(c => c.Type == ClaimTypes.Role)
            .Select(r => r.Value)
            .ToList();

        return Ok(new
        {
            Username = username,
            Roles = roles
        });
    }


}

public class RegisterDto
{
    [Required]
    public string Username { get; set; }
    [Required]
    [EmailAddress]
    public string Email { get; set; }
    [Required]
    public string Password { get; set; }
}

public class LoginDto
{
    [Required]
    public string Username { get; set; }
    [Required]
    public string Password { get; set; }
}

