using VulnMgmt.Web.Models.Domain;
using VulnMgmt.Web.Models.ViewModels;

namespace VulnMgmt.Web.Services;

public interface IReportService
{
    /// <summary>
    /// Export vulnerabilities to CSV
    /// </summary>
    Task<byte[]> ExportVulnerabilitiesToCsvAsync(VulnerabilityExportCriteria criteria);

    /// <summary>
    /// Export vulnerabilities to Excel
    /// </summary>
    Task<byte[]> ExportVulnerabilitiesToExcelAsync(VulnerabilityExportCriteria criteria);

    /// <summary>
    /// Get vulnerability summary report data
    /// </summary>
    Task<VulnerabilitySummaryReport> GetVulnerabilitySummaryAsync(int? siteId = null);

    /// <summary>
    /// Get host summary report data
    /// </summary>
    Task<HostSummaryReport> GetHostSummaryAsync(int? siteId = null);
}

public class VulnerabilityExportCriteria
{
    public int? SiteId { get; set; }
    public int? HostId { get; set; }
    public Severity? MinimumSeverity { get; set; }
    public RemediationStatus? Status { get; set; }
    public bool? IsExploitable { get; set; }
    public bool IncludeRemediated { get; set; } = false;
}

public class VulnerabilitySummaryReport
{
    public string? SiteName { get; set; }
    public DateTime GeneratedDate { get; set; } = DateTime.UtcNow;
    public int TotalVulnerabilities { get; set; }
    public int TotalHosts { get; set; }
    public Dictionary<Severity, int> BySeverity { get; set; } = new();
    public Dictionary<RemediationStatus, int> ByStatus { get; set; } = new();
    public int ExploitableCount { get; set; }
    public List<TopVulnerability> TopVulnerabilities { get; set; } = new();
    public List<HostRiskSummary> HighRiskHosts { get; set; } = new();
}

public class TopVulnerability
{
    public int PluginId { get; set; }
    public string PluginName { get; set; } = string.Empty;
    public Severity Severity { get; set; }
    public int AffectedHostCount { get; set; }
    public bool IsExploitable { get; set; }
    public string? CVE { get; set; }
}

public class HostRiskSummary
{
    public int HostId { get; set; }
    public string HostName { get; set; } = string.Empty;
    public string? IPAddress { get; set; }
    public int CriticalCount { get; set; }
    public int HighCount { get; set; }
    public int MediumCount { get; set; }
    public int TotalVulnerabilities { get; set; }
}

public class HostSummaryReport
{
    public string? SiteName { get; set; }
    public DateTime GeneratedDate { get; set; } = DateTime.UtcNow;
    public int TotalHosts { get; set; }
    public int ActiveHosts { get; set; }
    public int HostsWithVulnerabilities { get; set; }
    public Dictionary<AssetType, int> ByAssetType { get; set; } = new();
    public Dictionary<HostStatus, int> ByStatus { get; set; } = new();
    public List<HostRiskSummary> AllHosts { get; set; } = new();
}
