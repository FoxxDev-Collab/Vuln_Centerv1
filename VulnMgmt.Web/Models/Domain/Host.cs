using System.ComponentModel.DataAnnotations;

namespace VulnMgmt.Web.Models.Domain;

public class Host
{
    public int Id { get; set; }

    public int SiteId { get; set; }

    [StringLength(255)]
    public string? DNSName { get; set; }

    [StringLength(15)]
    public string? NetBIOSName { get; set; }

    [StringLength(100)]
    public string? DisplayName { get; set; }

    [StringLength(500)]
    public string? Description { get; set; }

    [StringLength(200)]
    public string? OperatingSystem { get; set; }

    [StringLength(100)]
    public string? OSVersion { get; set; }

    [StringLength(45)]
    public string? LastKnownIPAddress { get; set; }

    [StringLength(17)]
    public string? LastKnownMACAddress { get; set; }

    public AssetType AssetType { get; set; } = AssetType.Unknown;

    [StringLength(50)]
    public string? AssetTag { get; set; }

    [StringLength(50)]
    public string? SerialNumber { get; set; }

    public HostStatus Status { get; set; } = HostStatus.Unknown;

    public DateTime? LastScanDate { get; set; }

    public int LastScanVulnCount { get; set; }

    public DateTime CreatedDate { get; set; } = DateTime.UtcNow;

    public DateTime ModifiedDate { get; set; } = DateTime.UtcNow;

    // Navigation properties
    public virtual Site Site { get; set; } = null!;
    public virtual ICollection<HostVulnerability> Vulnerabilities { get; set; } = new List<HostVulnerability>();
}
