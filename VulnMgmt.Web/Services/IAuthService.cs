using VulnMgmt.Web.Models.Domain;

namespace VulnMgmt.Web.Services;

public interface IAuthService
{
    Task<User?> AuthenticateAsync(string username, string password);
    Task<User?> GetOrCreateWindowsUserAsync(string windowsUsername);
    Task<User?> GetUserByIdAsync(int id);
    Task<User?> GetUserByUsernameAsync(string username);
    string HashPassword(string password);
    bool VerifyPassword(string password, string hash);
}
