using System.ComponentModel.DataAnnotations;

namespace VulnMgmt.Web.Models.Domain;

/// <summary>
/// Represents an individual STIG rule/requirement within a benchmark version.
/// </summary>
public class StigRule
{
    public int Id { get; set; }

    public int BenchmarkVersionId { get; set; }
    public StigBenchmarkVersion BenchmarkVersion { get; set; } = null!;

    /// <summary>
    /// Vulnerability ID (e.g., "V-220697")
    /// </summary>
    [Required]
    [MaxLength(50)]
    public string VulnId { get; set; } = string.Empty;

    /// <summary>
    /// Rule ID (e.g., "SV-220697r991589_rule")
    /// </summary>
    [Required]
    [MaxLength(100)]
    public string RuleId { get; set; } = string.Empty;

    /// <summary>
    /// Group ID - same as VulnId in most cases
    /// </summary>
    [MaxLength(50)]
    public string? GroupId { get; set; }

    /// <summary>
    /// Group title / SRG reference (e.g., "SRG-OS-000480-GPOS-00227")
    /// </summary>
    [MaxLength(500)]
    public string? GroupTitle { get; set; }

    /// <summary>
    /// Severity level (CAT I = High, CAT II = Medium, CAT III = Low)
    /// </summary>
    public StigSeverity Severity { get; set; }

    /// <summary>
    /// Rule version identifier (e.g., "WN10-00-000005")
    /// </summary>
    [MaxLength(100)]
    public string? RuleVersion { get; set; }

    /// <summary>
    /// Short title of the rule
    /// </summary>
    [Required]
    [MaxLength(1000)]
    public string RuleTitle { get; set; } = string.Empty;

    /// <summary>
    /// Detailed description/discussion of the vulnerability
    /// </summary>
    public string? Discussion { get; set; }

    /// <summary>
    /// Check content - how to verify compliance
    /// </summary>
    public string? CheckContent { get; set; }

    /// <summary>
    /// Fix text - how to remediate
    /// </summary>
    public string? FixText { get; set; }

    /// <summary>
    /// Comma-separated list of CCIs (e.g., "CCI-000366,CCI-000367")
    /// </summary>
    [MaxLength(1000)]
    public string? CCIs { get; set; }

    /// <summary>
    /// Comma-separated list of legacy IDs
    /// </summary>
    [MaxLength(500)]
    public string? LegacyIds { get; set; }

    /// <summary>
    /// Weight value from XCCDF
    /// </summary>
    public decimal? Weight { get; set; }

    // Navigation
    public ICollection<StigChecklistResult> ChecklistResults { get; set; } = new List<StigChecklistResult>();
}
