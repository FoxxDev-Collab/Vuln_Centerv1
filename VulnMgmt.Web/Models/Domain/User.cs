using System.ComponentModel.DataAnnotations;

namespace VulnMgmt.Web.Models.Domain;

public class User
{
    public int Id { get; set; }

    [Required]
    [StringLength(100)]
    public string Username { get; set; } = string.Empty;

    [StringLength(200)]
    [EmailAddress]
    public string? Email { get; set; }

    [StringLength(100)]
    public string? DisplayName { get; set; }

    [StringLength(20)]
    public string? Phone { get; set; }

    [StringLength(500)]
    public string? PasswordHash { get; set; }

    public UserRole Role { get; set; } = UserRole.Auditor;

    public bool IsWindowsAuth { get; set; }

    public bool IsActive { get; set; } = true;

    public DateTime CreatedDate { get; set; } = DateTime.UtcNow;

    public DateTime ModifiedDate { get; set; } = DateTime.UtcNow;

    public DateTime? LastLoginDate { get; set; }

    // Navigation properties
    public virtual ICollection<ScanImport> ScanImports { get; set; } = new List<ScanImport>();
    public virtual ICollection<AuditLog> AuditLogs { get; set; } = new List<AuditLog>();
}
