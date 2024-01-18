using System.ComponentModel.DataAnnotations;

namespace IdentityServer.Models
{
    public class RoleModel
    {
        [Required(ErrorMessage = "Role Name is required")]
        public string? RoleName { get; set; }
    }
}
