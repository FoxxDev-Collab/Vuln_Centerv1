using VulnMgmt.Web.Models.Domain;

namespace VulnMgmt.Web.Services;

public interface IUserService
{
    Task<IEnumerable<User>> GetAllAsync();
    Task<User?> GetByIdAsync(int id);
    Task<User?> GetByUsernameAsync(string username);
    Task<User> CreateAsync(User user, string? password = null);
    Task<User> UpdateAsync(User user);
    Task UpdatePasswordAsync(int userId, string newPassword);
    Task DeleteAsync(int id);
    Task<bool> ExistsAsync(int id);
    Task<bool> UsernameExistsAsync(string username, int? excludeUserId = null);
    Task ToggleActiveAsync(int id);
}
