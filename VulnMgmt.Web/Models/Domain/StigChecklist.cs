using System.ComponentModel.DataAnnotations;

namespace VulnMgmt.Web.Models.Domain;

/// <summary>
/// Represents a point-in-time STIG checklist for a Host.
/// Links a host to a specific benchmark version with results.
/// </summary>
public class StigChecklist
{
    public int Id { get; set; }

    /// <summary>
    /// The host this checklist is for
    /// </summary>
    public int HostId { get; set; }
    public Host Host { get; set; } = null!;

    /// <summary>
    /// The specific STIG benchmark version being evaluated
    /// </summary>
    public int BenchmarkVersionId { get; set; }
    public StigBenchmarkVersion BenchmarkVersion { get; set; } = null!;

    /// <summary>
    /// Custom title for the checklist
    /// </summary>
    [MaxLength(500)]
    public string? Title { get; set; }

    /// <summary>
    /// Current status of the checklist
    /// </summary>
    public ChecklistStatus Status { get; set; } = ChecklistStatus.Draft;

    /// <summary>
    /// User who created the checklist
    /// </summary>
    public int? CreatedById { get; set; }
    public User? CreatedBy { get; set; }

    /// <summary>
    /// User who last modified the checklist
    /// </summary>
    public int? LastModifiedById { get; set; }
    public User? LastModifiedBy { get; set; }

    /// <summary>
    /// Source file if imported (CKLB or XCCDF results)
    /// </summary>
    [MaxLength(500)]
    public string? ImportSource { get; set; }

    public DateTime CreatedDate { get; set; } = DateTime.UtcNow;
    public DateTime LastModifiedDate { get; set; } = DateTime.UtcNow;

    // Computed statistics
    public int NotReviewedCount { get; set; }
    public int OpenCount { get; set; }
    public int NotAFindingCount { get; set; }
    public int NotApplicableCount { get; set; }

    // Navigation
    public ICollection<StigChecklistResult> Results { get; set; } = new List<StigChecklistResult>();
}
