using IdentityApplication.Models;
using IdentityServer.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Routing;
using Microsoft.AspNetCore.Rewrite;
using Microsoft.IdentityModel.Tokens;
using Microsoft.VisualBasic;
using Microsoft.Win32;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Text;

namespace IdentityServer.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;

        public AccountController(
            UserManager<ApplicationUser> userManager,
            RoleManager<IdentityRole> roleManager,
            IConfiguration configuration
            )
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
        }
        [HttpPost]
        [Route("register")]
        public async Task<IActionResult> Register([FromBody] RegisterModel registerModel)
        {

            var userExist= await _userManager.FindByEmailAsync(registerModel.Email);
            //check if user exist
            if (userExist != null)
            {
                return BadRequest(new ApiResponse<string>((int)StatusCodes.Status400BadRequest, false, "user already exist"));
            }
            else
            {
                //Add the User in the database
                ApplicationUser user = new ApplicationUser()
                {
                    UserName = registerModel.Email,
                    Email = registerModel.Email,
                    EmailConfirmed = false,
                    PhoneNumberConfirmed = true,
                    SecurityStamp = Guid.NewGuid().ToString(),
                    IsTemporaryPassword = registerModel.IsTemporaryPassword
                };
                if(await _roleManager.RoleExistsAsync(registerModel.UserType))
                {
                    var result = await _userManager.CreateAsync(user, registerModel.Password);
                    if (result.Succeeded)
                    {
                        await _userManager.AddToRoleAsync(user, registerModel.UserType);
                        return Ok(new ApiResponse<string>((int)StatusCodes.Status200OK, true, "User Created successfully"));
                    }
                    else
                    {
                        return BadRequest(new ApiResponse<string>((int)HttpStatusCode.InternalServerError, false, "Problem in User Created"));
                    }
                }
                else
                {
                    return BadRequest(new ApiResponse<string>((int)HttpStatusCode.InternalServerError, false, "Problem in User Created"));
                }
              
            }
        }
        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel loginModel)
        {
            try
            {
                var user = await _userManager.FindByEmailAsync(loginModel.Email); ;
                if (user != null && await _userManager.CheckPasswordAsync(user, loginModel.Password))
                {
                    var userRoles = await _userManager.GetRolesAsync(user);

                    var authClaims = new List<Claim>
                        {
                            new Claim(ClaimTypes.Name, user.UserName),
                            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                        };

                    foreach (var userRole in userRoles)
                    {
                        authClaims.Add(new Claim(ClaimTypes.Role, userRole));
                    }

                    var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));

                    var signingCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

                    var token = new JwtSecurityToken(
                                        _configuration["JWT:ValidIssuer"],
                                        _configuration["JWT:ValidAudience"],
                                        authClaims,
                                        expires: DateTime.Now.AddMinutes(30),
                                        signingCredentials: signingCredentials);
                    var result = new LoginResponseModel
                    {
                        Email = loginModel.Email,
                        Token = new JwtSecurityTokenHandler().WriteToken(token),
                        Expiration = token.ValidTo,
                        UserType = userRoles.ToList(),
                        IsEmailConfirmed = user.EmailConfirmed,
                        IsTemporaryPassword = user.IsTemporaryPassword
                    };
                    return Ok(new ApiResponse<LoginResponseModel>() { Data = result, StatusCode = (int)StatusCodes.Status200OK, Success = true, Message = "Logged in successfully !!" });

                }
                return BadRequest(new ApiResponse<string>((int)StatusCodes.Status400BadRequest, false, "Please check credentials, wrong username or password."));
            }
            catch (Exception ex)
            {
                return BadRequest(new ApiResponse<string>((int)StatusCodes.Status500InternalServerError, false, ex.Message));
            }

        }
        [HttpPost]
        [Route("CreateRole")]
        public async Task<IActionResult> CreateRole(RoleModel role)
        {
            if (!await _roleManager.RoleExistsAsync(role.RoleName))
            {
                var result = await _roleManager.CreateAsync(new IdentityRole(role.RoleName));
                if (!result.Succeeded)
                {
                    return BadRequest(new ApiResponse<string>((int)StatusCodes.Status400BadRequest, false, "Problem in Created role "));
                }
                return Ok(new ApiResponse<string>() {StatusCode = (int)StatusCodes.Status200OK, Success = true, Message = "Role Created successfully !!" });
            }
            return BadRequest(new ApiResponse<string>((int)StatusCodes.Status400BadRequest, false, "Problem in Created role "));
        }
        [HttpPost]
        [Route("getemailconfirmationtoken")]
        public async Task<IActionResult> GetEmailConfirmationToken([FromBody] string emailId)
        {
            var user = await _userManager.FindByEmailAsync(emailId);
            var emailConfirmationToken = await _userManager.GenerateEmailConfirmationTokenAsync(user);

            return Ok(new Response(new
            {
                EmailConfirmationToken = emailConfirmationToken
            }));
        }
        [HttpPost]
        [Route("confirmemail")]
        public async Task<IActionResult> ConfirmEmail([FromBody] EmailConfirmation emailConfirmation)
        {
            try
            {
                var user = await _userManager.FindByEmailAsync(emailConfirmation.Email);
                if (user == null)
                {
                    return BadRequest(new ApiResponse<string>((int)StatusCodes.Status400BadRequest, false, "Records not found !!"));
                }

                var result = await _userManager.ConfirmEmailAsync(user, emailConfirmation.Token);
                if (result != null && result.Succeeded == true)
                {
                    return Ok(new ApiResponse<string>((int)StatusCodes.Status200OK, true, "Email Confirmed successfully!"));
                }
                return BadRequest(new ApiResponse<string>((int)StatusCodes.Status500InternalServerError, false, result.Errors.FirstOrDefault()?.Description?.ToString()));
            }
            catch (Exception ex)
            {
                return BadRequest(new ApiResponse<string>((int)StatusCodes.Status500InternalServerError, false, ex.Message));
            }
        }
        [HttpPost]
        [Route("changepassword")]
        public async Task<IActionResult> ChangePassword(ChangePassword changePasswordModel)
        {
            try
            {
                if (changePasswordModel != null)
                {
                    ApplicationUser user = await _userManager.FindByEmailAsync(changePasswordModel.Email);
                    if (user == null)
                    {
                        return BadRequest(new ApiResponse<string>((int)HttpStatusCode.NotFound, false, "User not found."));
                    }

                    if (await _userManager.CheckPasswordAsync(user, changePasswordModel.OldPassword) && (changePasswordModel.NewPassword == changePasswordModel.ConfirmNewPassword))
                    {
                        var result = await _userManager.ChangePasswordAsync(user, changePasswordModel.OldPassword, changePasswordModel.NewPassword);
                        if (!result.Succeeded)
                        {
                            return BadRequest(new ApiResponse<string>((int)HttpStatusCode.NotFound, false, result.Errors.FirstOrDefault().Description.ToString()));
                        }

                        // TO DO: Update this flag only for temporary password.
                        user.IsTemporaryPassword = false;
                        await _userManager.UpdateAsync(user);

                        return Ok(new ApiResponse<string>((int)StatusCodes.Status200OK, true, "Password updated successfully"));
                    }
                    return BadRequest(new ApiResponse<string>((int)HttpStatusCode.InternalServerError, false, "Current Password doesn't match."));
                }
                return BadRequest(new ApiResponse<string>((int)HttpStatusCode.InternalServerError, false, "changePasswordModel model should not be null."));
            }
            catch (Exception ex)
            {
                return BadRequest(new ApiResponse<string>((int)StatusCodes.Status500InternalServerError, false, ex.Message));
            }
        }
        [HttpPost]
        [Route("forgotpassword")]
        public async Task<IActionResult> ForgotPassword([FromBody] ForgotPassword forgotPassword)
        {
            try
            {
                ApplicationUser user = await _userManager.FindByEmailAsync(forgotPassword.Email);
                if (user == null)
                {
                    return BadRequest(new ApiResponse<string>((int)HttpStatusCode.NotFound, false, "User doesn't exist."));
                }
                var token = await _userManager.GeneratePasswordResetTokenAsync(user);
                var result = new PasswordReceipt
                {
                    Token = token
                };
                return Ok(new ApiResponse<PasswordReceipt>() { Data = result, StatusCode = (int)StatusCodes.Status200OK, Success = true, Message = "ForgotPassword token updated successfully" });
            }
            catch (Exception ex)
            {
                return BadRequest(new ApiResponse<string>((int)HttpStatusCode.InternalServerError, false, ex.Message));
            }
        }

        [HttpPost]
        [Route("resetpassword")]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordModel resetPasswordModel)
        {
            try
            {
                var user = await _userManager.FindByEmailAsync(resetPasswordModel.Email);
                if (user == null)
                {
                    return BadRequest(new ApiResponse<string>((int)HttpStatusCode.NotFound, false, "User doesn't exist."));
                }
                var resetPassResult = await _userManager.ResetPasswordAsync(user, resetPasswordModel.Token, resetPasswordModel.Password);
                if (!resetPassResult.Succeeded)
                {
                    return BadRequest(new ApiResponse<string>((int)HttpStatusCode.InternalServerError, false, resetPassResult.Errors.FirstOrDefault().Description));
                }
                return Ok(new ApiResponse<string>((int)StatusCodes.Status200OK, true, "Password reset successful !!"));
            }
            catch (Exception ex)
            {
                return BadRequest(new ApiResponse<string>((int)HttpStatusCode.InternalServerError, false, ex.Message));
            }
        }
        [HttpPost]
        [Route("deleteuser")]
        public async Task<IActionResult> DeleteUser([FromBody] string emailId)
        {

            try
            {
                var user = await _userManager.FindByEmailAsync(emailId);
                var result = await _userManager.DeleteAsync(user);
                if (result != null && result.Succeeded == true)
                {
                    return Ok(new ApiResponse<string>((int)StatusCodes.Status200OK, true, "User deleted successfully!"));
                }
                return BadRequest(new ApiResponse<string>((int)StatusCodes.Status500InternalServerError, false, result.Errors.FirstOrDefault()?.Description?.ToString()));
            }
            catch (Exception ex)
            {
                return BadRequest(new ApiResponse<string>((int)StatusCodes.Status500InternalServerError, false, ex.Message));
            }
        }
    }
}
