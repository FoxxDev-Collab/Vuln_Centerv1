using System.ComponentModel.DataAnnotations;

namespace VulnMgmt.Web.Models.Domain;

public class Site
{
    public int Id { get; set; }

    [Required]
    [StringLength(100)]
    public string Name { get; set; } = string.Empty;

    [StringLength(500)]
    public string? Description { get; set; }

    [StringLength(200)]
    public string? Location { get; set; }

    [StringLength(200)]
    public string? OrganizationName { get; set; }

    [StringLength(100)]
    public string? POCName { get; set; }

    [StringLength(100)]
    [EmailAddress]
    public string? POCEmail { get; set; }

    [StringLength(20)]
    public string? POCPhone { get; set; }

    public bool IsActive { get; set; } = true;

    public DateTime CreatedDate { get; set; } = DateTime.UtcNow;

    public DateTime ModifiedDate { get; set; } = DateTime.UtcNow;

    // Navigation properties
    public virtual ICollection<Host> Hosts { get; set; } = new List<Host>();
    public virtual ICollection<ScanImport> ScanImports { get; set; } = new List<ScanImport>();
}
