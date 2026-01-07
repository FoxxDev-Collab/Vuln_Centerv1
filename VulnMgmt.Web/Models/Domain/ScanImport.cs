using System.ComponentModel.DataAnnotations;

namespace VulnMgmt.Web.Models.Domain;

public class ScanImport
{
    public int Id { get; set; }

    public int SiteId { get; set; }

    [Required]
    [StringLength(500)]
    public string FileName { get; set; } = string.Empty;

    public DateTime ImportDate { get; set; } = DateTime.UtcNow;

    public int TotalRows { get; set; }

    public int HostsCreated { get; set; }

    public int HostsUpdated { get; set; }

    public int VulnerabilitiesImported { get; set; }

    public int VulnerabilitiesUpdated { get; set; }

    public int? ImportedById { get; set; }

    [StringLength(1000)]
    public string? Notes { get; set; }

    // Navigation properties
    public virtual Site Site { get; set; } = null!;
    public virtual User? ImportedBy { get; set; }
}
