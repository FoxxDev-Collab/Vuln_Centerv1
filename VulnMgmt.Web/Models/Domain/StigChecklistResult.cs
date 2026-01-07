using System.ComponentModel.DataAnnotations;

namespace VulnMgmt.Web.Models.Domain;

/// <summary>
/// Represents the result for a single STIG rule within a checklist.
/// </summary>
public class StigChecklistResult
{
    public int Id { get; set; }

    public int ChecklistId { get; set; }
    public StigChecklist Checklist { get; set; } = null!;

    public int StigRuleId { get; set; }
    public StigRule StigRule { get; set; } = null!;

    /// <summary>
    /// The compliance status for this rule
    /// </summary>
    public StigResultStatus Status { get; set; } = StigResultStatus.NotReviewed;

    /// <summary>
    /// Detailed finding information (evidence, observations)
    /// </summary>
    public string? FindingDetails { get; set; }

    /// <summary>
    /// Additional comments
    /// </summary>
    public string? Comments { get; set; }

    /// <summary>
    /// If severity is overridden, the justification
    /// </summary>
    [MaxLength(2000)]
    public string? SeverityOverrideJustification { get; set; }

    /// <summary>
    /// Override severity (null = use rule's default severity)
    /// </summary>
    public StigSeverity? SeverityOverride { get; set; }

    /// <summary>
    /// User who last modified this result
    /// </summary>
    public int? ModifiedById { get; set; }
    public User? ModifiedBy { get; set; }

    public DateTime LastModifiedDate { get; set; } = DateTime.UtcNow;
}
