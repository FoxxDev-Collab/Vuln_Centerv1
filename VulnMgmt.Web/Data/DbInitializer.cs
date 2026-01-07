using VulnMgmt.Web.Models.Domain;

namespace VulnMgmt.Web.Data;

public static class DbInitializer
{
    public static void Initialize(ApplicationDbContext context)
    {
        context.Database.EnsureCreated();

        // Check if we already have data
        if (context.Users.Any())
        {
            return;
        }

        // Create default admin user
        var adminUser = new User
        {
            Username = "admin",
            DisplayName = "System Administrator",
            Email = "admin@localhost",
            Role = UserRole.Admin,
            IsWindowsAuth = false,
            IsActive = true,
            // Default password: "Admin123!" - should be changed on first login
            PasswordHash = BCrypt.Net.BCrypt.HashPassword("Admin123!")
        };
        context.Users.Add(adminUser);

        // Create a sample site
        var sampleSite = new Site
        {
            Name = "Default Site",
            Description = "Default site for vulnerability tracking",
            Location = "Main Office",
            OrganizationName = "IT Security",
            IsActive = true
        };
        context.Sites.Add(sampleSite);

        context.SaveChanges();
    }
}
