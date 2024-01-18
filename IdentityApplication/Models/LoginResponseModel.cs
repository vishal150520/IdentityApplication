namespace IdentityApplication.Models
{
    public class LoginResponseModel
    {
        public LoginResponseModel()
        {
            UserType = new List<string>();
        }
        public string? Email { get; set; }
        public List<string> UserType { get; set; }
        public string? Token { get; set; }
        public DateTime Expiration { get; set; }
        public bool IsEmailConfirmed { get; set; }
        public bool IsTemporaryPassword { get; set; }
    }
}
