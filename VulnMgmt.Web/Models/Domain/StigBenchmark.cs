using System.ComponentModel.DataAnnotations;

namespace VulnMgmt.Web.Models.Domain;

/// <summary>
/// Represents a STIG benchmark (e.g., "Microsoft Windows 10 STIG").
/// This is the parent entity that groups all versions of a specific STIG.
/// </summary>
public class StigBenchmark
{
    public int Id { get; set; }

    /// <summary>
    /// The STIG identifier from the XML (e.g., "MS_Windows_10_STIG")
    /// </summary>
    [Required]
    [MaxLength(200)]
    public string StigId { get; set; } = string.Empty;

    /// <summary>
    /// Human-readable title (e.g., "Microsoft Windows 10 STIG")
    /// </summary>
    [Required]
    [MaxLength(500)]
    public string Title { get; set; } = string.Empty;

    [MaxLength(2000)]
    public string? Description { get; set; }

    /// <summary>
    /// The currently active version for this benchmark
    /// </summary>
    public int? CurrentVersionId { get; set; }
    public StigBenchmarkVersion? CurrentVersion { get; set; }

    public DateTime CreatedDate { get; set; } = DateTime.UtcNow;
    public DateTime ModifiedDate { get; set; } = DateTime.UtcNow;

    // Navigation
    public ICollection<StigBenchmarkVersion> Versions { get; set; } = new List<StigBenchmarkVersion>();
}
