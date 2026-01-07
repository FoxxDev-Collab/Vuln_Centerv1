using System.ComponentModel.DataAnnotations;

namespace VulnMgmt.Web.Models.Domain;

public class AuditLog
{
    public int Id { get; set; }

    public int? UserId { get; set; }

    [Required]
    [StringLength(100)]
    public string Action { get; set; } = string.Empty;

    [StringLength(100)]
    public string? EntityType { get; set; }

    public int? EntityId { get; set; }

    public string? OldValues { get; set; }

    public string? NewValues { get; set; }

    public DateTime Timestamp { get; set; } = DateTime.UtcNow;

    [StringLength(45)]
    public string? IpAddress { get; set; }

    // Navigation properties
    public virtual User? User { get; set; }
}
