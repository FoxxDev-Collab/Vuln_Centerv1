using System.ComponentModel.DataAnnotations;

namespace VulnMgmt.Web.Models.Domain;

/// <summary>
/// Represents a specific version of a STIG benchmark.
/// Multiple versions can exist (e.g., Oct 2024 and Jan 2025 versions).
/// </summary>
public class StigBenchmarkVersion
{
    public int Id { get; set; }

    public int StigBenchmarkId { get; set; }
    public StigBenchmark StigBenchmark { get; set; } = null!;

    /// <summary>
    /// Version number from XML (e.g., "3")
    /// </summary>
    [Required]
    [MaxLength(50)]
    public string Version { get; set; } = string.Empty;

    /// <summary>
    /// Release number from XML (e.g., "4")
    /// </summary>
    [MaxLength(50)]
    public string? Release { get; set; }

    /// <summary>
    /// Full release info text (e.g., "Release: 4 Benchmark Date: 02 Apr 2025")
    /// </summary>
    [MaxLength(500)]
    public string? ReleaseInfo { get; set; }

    /// <summary>
    /// The date the benchmark was published by DISA
    /// </summary>
    public DateTime? BenchmarkDate { get; set; }

    /// <summary>
    /// Original filename that was imported
    /// </summary>
    [MaxLength(500)]
    public string? FileName { get; set; }

    /// <summary>
    /// Date this version was imported into the system
    /// </summary>
    public DateTime ImportDate { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Number of rules in this version
    /// </summary>
    public int RuleCount { get; set; }

    /// <summary>
    /// Whether this is the current/active version for the benchmark
    /// </summary>
    public bool IsActive { get; set; }

    // Navigation
    public ICollection<StigRule> Rules { get; set; } = new List<StigRule>();
    public ICollection<StigChecklist> Checklists { get; set; } = new List<StigChecklist>();
}
