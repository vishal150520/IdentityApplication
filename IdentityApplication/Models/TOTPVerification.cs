namespace IdentityApplication.Models
{
    public class TOTPVerification
    {
        public string? TOTPSecret { get; set; } 
        public string? TOTPCode { get; set; }
        public string? Email { get; set; }
    }
}
