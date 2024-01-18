using System.ComponentModel.DataAnnotations;

namespace IdentityServer.Models
{
    public class ChangePassword
    {
        [Required(ErrorMessage = "Email is required")]
        public string? Email { get; set; }

        [Required(ErrorMessage = "Old Password is required")]
        public string? OldPassword { get; set; }

        [Required(ErrorMessage = "New Password is required")]
        public string? NewPassword { get; set; }

        [Required(ErrorMessage = "Confirm New Password is required")]
        public string? ConfirmNewPassword { get; set; }

    }
}
