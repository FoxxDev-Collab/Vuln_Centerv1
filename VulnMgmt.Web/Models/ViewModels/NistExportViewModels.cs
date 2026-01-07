using System.Text.Json.Serialization;
using VulnMgmt.Web.Models.Domain;

namespace VulnMgmt.Web.Models.ViewModels;

#region Export DTOs (for JSON serialization)

/// <summary>
/// Root object for the NIST Compliance Export JSON
/// </summary>
public class NistComplianceExport
{
    public ExportMetadata ExportMetadata { get; set; } = new();
    public SiteExport Site { get; set; } = new();
    public ExportSummary Summary { get; set; } = new();
    public List<HostExport> Hosts { get; set; } = new();
    public List<CciSummaryItem> CciSummary { get; set; } = new();
}

public class ExportMetadata
{
    public DateTime ExportDate { get; set; } = DateTime.UtcNow;
    public string? ExportedBy { get; set; }
    public string ApplicationName { get; set; } = "Vulnerability Management Center";
    public string ApplicationVersion { get; set; } = "1.0.0";
    public string ExportType { get; set; } = "ATO_COMPLIANCE_PACKAGE";
    public string ExportFormat { get; set; } = "NIST_COMPLIANCE_V1";
}

public class SiteExport
{
    public int Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public string? Location { get; set; }
    public string? OrganizationName { get; set; }
    public bool IsActive { get; set; }
    public DateTime CreatedDate { get; set; }
    public DateTime ModifiedDate { get; set; }
    public PointOfContact Poc { get; set; } = new();
}

public class PointOfContact
{
    public string? Name { get; set; }
    public string? Email { get; set; }
    public string? Phone { get; set; }
}

public class ExportSummary
{
    public int TotalHosts { get; set; }
    public StigChecklistSummary StigChecklists { get; set; } = new();
    public NessusVulnerabilitySummary NessusVulnerabilities { get; set; } = new();
    public CciCoverageSummary CciCoverage { get; set; } = new();
}

public class StigChecklistSummary
{
    public int TotalChecklists { get; set; }
    public int TotalRuleResults { get; set; }
    public int Open { get; set; }
    public int NotAFinding { get; set; }
    public int NotApplicable { get; set; }
    public int NotReviewed { get; set; }
}

public class NessusVulnerabilitySummary
{
    public int Total { get; set; }
    public int Critical { get; set; }
    public int High { get; set; }
    public int Medium { get; set; }
    public int Low { get; set; }
    public int Info { get; set; }
    public int Exploitable { get; set; }
    public RemediationStatusSummary ByRemediationStatus { get; set; } = new();
}

public class RemediationStatusSummary
{
    public int Open { get; set; }
    public int InProgress { get; set; }
    public int Remediated { get; set; }
    public int Accepted { get; set; }
    public int FalsePositive { get; set; }
}

public class CciCoverageSummary
{
    public int TotalUniqueCcis { get; set; }
    public int CcisWithOpenFindings { get; set; }
}

#region Host Export

public class HostExport
{
    public int Id { get; set; }
    public string? DnsName { get; set; }
    public string? NetBIOSName { get; set; }
    public string? DisplayName { get; set; }
    public string? IpAddress { get; set; }
    public string? MacAddress { get; set; }
    public string? OperatingSystem { get; set; }
    public string? OsVersion { get; set; }

    [JsonConverter(typeof(JsonStringEnumConverter))]
    public AssetType AssetType { get; set; }

    public string? AssetTag { get; set; }
    public string? SerialNumber { get; set; }

    [JsonConverter(typeof(JsonStringEnumConverter))]
    public HostStatus Status { get; set; }

    public DateTime? LastScanDate { get; set; }
    public int? LastScanVulnCount { get; set; }
    public DateTime CreatedDate { get; set; }
    public DateTime ModifiedDate { get; set; }

    public List<StigChecklistExport> StigChecklists { get; set; } = new();
    public List<NessusVulnerabilityExport> NessusVulnerabilities { get; set; } = new();
}

#endregion

#region STIG Checklist Export

public class StigChecklistExport
{
    public int Id { get; set; }
    public BenchmarkInfoExport BenchmarkInfo { get; set; } = new();
    public string? Title { get; set; }

    [JsonConverter(typeof(JsonStringEnumConverter))]
    public ChecklistStatus Status { get; set; }

    public string? ImportSource { get; set; }
    public DateTime CreatedDate { get; set; }
    public DateTime LastModifiedDate { get; set; }
    public string? CreatedBy { get; set; }
    public string? LastModifiedBy { get; set; }

    public ChecklistStatistics Statistics { get; set; } = new();
    public List<StigResultExport> Results { get; set; } = new();
}

public class BenchmarkInfoExport
{
    public int BenchmarkId { get; set; }
    public int BenchmarkVersionId { get; set; }
    public string StigId { get; set; } = string.Empty;
    public string Title { get; set; } = string.Empty;
    public string? Description { get; set; }
    public string Version { get; set; } = string.Empty;
    public string? Release { get; set; }
    public string? ReleaseInfo { get; set; }
    public DateTime? BenchmarkDate { get; set; }
    public int RuleCount { get; set; }
}

public class ChecklistStatistics
{
    public int TotalRules { get; set; }
    public int NotReviewed { get; set; }
    public int Open { get; set; }
    public int NotAFinding { get; set; }
    public int NotApplicable { get; set; }
}

public class StigResultExport
{
    // Rule identification
    public string VulnId { get; set; } = string.Empty;
    public string RuleId { get; set; } = string.Empty;
    public string? GroupId { get; set; }
    public string? GroupTitle { get; set; }
    public string? RuleVersion { get; set; }
    public string RuleTitle { get; set; } = string.Empty;

    // Severity
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public StigSeverity Severity { get; set; }

    public StigSeverity? SeverityOverride { get; set; }
    public string? SeverityOverrideJustification { get; set; }

    // Result status
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public StigResultStatus Status { get; set; }

    public string? FindingDetails { get; set; }
    public string? Comments { get; set; }

    // CCIs for NIST mapping
    public List<string> Ccis { get; set; } = new();
    public string? LegacyIds { get; set; }

    // Full rule content
    public string? Discussion { get; set; }
    public string? CheckContent { get; set; }
    public string? FixText { get; set; }

    // Audit info
    public DateTime LastModifiedDate { get; set; }
    public string? ModifiedBy { get; set; }
}

#endregion

#region Nessus Vulnerability Export

public class NessusVulnerabilityExport
{
    public int Id { get; set; }
    public int PluginId { get; set; }
    public string? PluginName { get; set; }
    public string? Family { get; set; }

    [JsonConverter(typeof(JsonStringEnumConverter))]
    public Severity Severity { get; set; }

    // Network info
    public string? IpAddress { get; set; }
    public string? Protocol { get; set; }
    public int? Port { get; set; }
    public string? MacAddress { get; set; }

    // Vulnerability details
    public string? Cve { get; set; }
    public DateTime? VulnPublicationDate { get; set; }
    public string? Synopsis { get; set; }
    public string? Description { get; set; }
    public string? Solution { get; set; }
    public string? SeeAlso { get; set; }
    public string? PluginText { get; set; }

    // Exploit info
    public bool IsExploitable { get; set; }
    public string? ExploitFrameworks { get; set; }
    public string? ExploitEase { get; set; }

    // Timeline
    public DateTime? FirstDiscovered { get; set; }
    public DateTime? LastObserved { get; set; }

    // Remediation
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public RemediationStatus RemediationStatus { get; set; }

    public string? RemediationNotes { get; set; }
    public DateTime? RemediationDate { get; set; }

    // Import info
    public string? ImportSource { get; set; }
}

#endregion

#region CCI Summary

public class CciSummaryItem
{
    public string CciId { get; set; } = string.Empty;
    public int TotalRuleCount { get; set; }
    public int OpenFindingCount { get; set; }
    public int NotAFindingCount { get; set; }
    public int NotApplicableCount { get; set; }
    public int NotReviewedCount { get; set; }
    public List<string> AffectedHosts { get; set; } = new();
    public List<string> AffectedVulnIds { get; set; } = new();
}

#endregion

#endregion

#region View Models (for the export form page)

public class NistExportViewModel
{
    public List<SiteSelectItem> Sites { get; set; } = new();
    public int? SelectedSiteId { get; set; }
    public NistExportPreview? Preview { get; set; }
}

public class SiteSelectItem
{
    public int Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public int HostCount { get; set; }
}

public class NistExportPreview
{
    public int SiteId { get; set; }
    public string SiteName { get; set; } = string.Empty;
    public int TotalHosts { get; set; }
    public int TotalStigChecklists { get; set; }
    public int TotalStigRuleResults { get; set; }
    public int TotalNessusVulnerabilities { get; set; }
    public int UniqueCciCount { get; set; }
    public DateTime? LastScanDate { get; set; }
}

#endregion
