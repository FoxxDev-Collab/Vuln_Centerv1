using Microsoft.EntityFrameworkCore;
using VulnMgmt.Web.Data;
using VulnMgmt.Web.Models.Domain;

namespace VulnMgmt.Web.Services;

public class AuthService : IAuthService
{
    private readonly ApplicationDbContext _context;

    public AuthService(ApplicationDbContext context)
    {
        _context = context;
    }

    public async Task<User?> AuthenticateAsync(string username, string password)
    {
        var user = await _context.Users
            .FirstOrDefaultAsync(u => u.Username == username && u.IsActive && !u.IsWindowsAuth);

        if (user == null)
            return null;

        if (string.IsNullOrEmpty(user.PasswordHash))
            return null;

        // Handle placeholder passwords from seeding
        if (user.PasswordHash.StartsWith("NEEDS_HASH:"))
        {
            var storedPassword = user.PasswordHash.Substring("NEEDS_HASH:".Length);
            if (password == storedPassword)
            {
                // Update to proper hash
                user.PasswordHash = HashPassword(password);
                user.ModifiedDate = DateTime.UtcNow;
                await _context.SaveChangesAsync();
                return user;
            }
            return null;
        }

        if (!VerifyPassword(password, user.PasswordHash))
            return null;

        return user;
    }

    public async Task<User?> GetOrCreateWindowsUserAsync(string windowsUsername)
    {
        var user = await _context.Users
            .FirstOrDefaultAsync(u => u.Username == windowsUsername && u.IsWindowsAuth);

        if (user != null)
            return user.IsActive ? user : null;

        // Create new Windows auth user with Auditor role by default (read-only)
        user = new User
        {
            Username = windowsUsername,
            DisplayName = ExtractDisplayName(windowsUsername),
            IsWindowsAuth = true,
            Role = UserRole.Auditor,
            IsActive = true
        };

        _context.Users.Add(user);
        await _context.SaveChangesAsync();

        return user;
    }

    public async Task<User?> GetUserByIdAsync(int id)
    {
        return await _context.Users.FindAsync(id);
    }

    public async Task<User?> GetUserByUsernameAsync(string username)
    {
        return await _context.Users
            .FirstOrDefaultAsync(u => u.Username == username);
    }

    public string HashPassword(string password)
    {
        return BCrypt.Net.BCrypt.HashPassword(password, workFactor: 12);
    }

    public bool VerifyPassword(string password, string hash)
    {
        try
        {
            return BCrypt.Net.BCrypt.Verify(password, hash);
        }
        catch
        {
            return false;
        }
    }

    private static string ExtractDisplayName(string windowsUsername)
    {
        // Extract username from DOMAIN\username format
        var parts = windowsUsername.Split('\\');
        return parts.Length > 1 ? parts[1] : windowsUsername;
    }
}
