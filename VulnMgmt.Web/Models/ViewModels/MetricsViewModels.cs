using VulnMgmt.Web.Models.Domain;

namespace VulnMgmt.Web.Models.ViewModels;

/// <summary>
/// Main view model for the ATO Metrics Dashboard
/// </summary>
public class AtoMetricsDashboardViewModel
{
    public AtoPackageOverview PackageOverview { get; set; } = new();
    public VulnerabilityMetrics VulnerabilityMetrics { get; set; } = new();
    public StigComplianceMetrics StigMetrics { get; set; } = new();
    public List<SiteMetricsSummary> SiteBreakdown { get; set; } = new();
    public DateTime GeneratedAt { get; set; } = DateTime.Now;
}

/// <summary>
/// High-level ATO package statistics
/// </summary>
public class AtoPackageOverview
{
    public int TotalSites { get; set; }
    public int TotalHosts { get; set; }
    public int ActiveHosts { get; set; }

    // Vulnerability summary
    public int TotalVulnerabilities { get; set; }
    public int OpenVulnerabilities { get; set; }
    public int CriticalVulnerabilities { get; set; }
    public int HighVulnerabilities { get; set; }
    public int ExploitableVulnerabilities { get; set; }

    // STIG summary
    public int TotalStigChecklists { get; set; }
    public int TotalStigFindings { get; set; }
    public int StigOpenFindings { get; set; }
    public int StigNotAFinding { get; set; }
    public int StigNotApplicable { get; set; }
    public int StigNotReviewed { get; set; }

    // Calculated scores
    public double OverallCompliancePercentage { get; set; }
    public double VulnerabilityRiskScore { get; set; }
    public string RiskLevel => VulnerabilityRiskScore switch
    {
        >= 80 => "Critical",
        >= 60 => "High",
        >= 40 => "Medium",
        >= 20 => "Low",
        _ => "Minimal"
    };
}

/// <summary>
/// Detailed vulnerability metrics for charts
/// </summary>
public class VulnerabilityMetrics
{
    // By Severity
    public int CriticalCount { get; set; }
    public int HighCount { get; set; }
    public int MediumCount { get; set; }
    public int LowCount { get; set; }
    public int InfoCount { get; set; }

    // By Status
    public int OpenCount { get; set; }
    public int InProgressCount { get; set; }
    public int RemediatedCount { get; set; }
    public int AcceptedCount { get; set; }
    public int FalsePositiveCount { get; set; }

    // Additional metrics
    public int ExploitableCount { get; set; }
    public int UniquePluginCount { get; set; }
    public int UniqueCveCount { get; set; }

    // Top vulnerabilities
    public List<TopVulnerabilityItem> TopVulnerabilities { get; set; } = new();

    // Chart data helpers
    public int[] SeverityData => new[] { CriticalCount, HighCount, MediumCount, LowCount, InfoCount };
    public int[] StatusData => new[] { OpenCount, InProgressCount, RemediatedCount, AcceptedCount, FalsePositiveCount };
}

/// <summary>
/// Top vulnerability item for display
/// </summary>
public class TopVulnerabilityItem
{
    public string PluginId { get; set; } = string.Empty;
    public string PluginName { get; set; } = string.Empty;
    public Severity Severity { get; set; }
    public int AffectedHostCount { get; set; }
    public bool IsExploitable { get; set; }
    public string? CVE { get; set; }
}

/// <summary>
/// STIG compliance metrics for charts
/// </summary>
public class StigComplianceMetrics
{
    // Overall counts
    public int TotalRulesEvaluated { get; set; }
    public int OpenCount { get; set; }
    public int NotAFindingCount { get; set; }
    public int NotApplicableCount { get; set; }
    public int NotReviewedCount { get; set; }

    // By CAT level
    public int CatITotal { get; set; }
    public int CatIOpen { get; set; }
    public int CatIITotal { get; set; }
    public int CatIIOpen { get; set; }
    public int CatIIITotal { get; set; }
    public int CatIIIOpen { get; set; }

    // Per-benchmark compliance
    public List<BenchmarkComplianceItem> BenchmarkCompliance { get; set; } = new();

    // Calculated
    public double CompliancePercentage => TotalRulesEvaluated > 0
        ? Math.Round((NotAFindingCount + NotApplicableCount) * 100.0 / TotalRulesEvaluated, 1)
        : 0;

    public double AssessmentCompletionPercentage => TotalRulesEvaluated > 0
        ? Math.Round((TotalRulesEvaluated - NotReviewedCount) * 100.0 / TotalRulesEvaluated, 1)
        : 0;

    // Chart data helpers
    public int[] StatusData => new[] { OpenCount, NotAFindingCount, NotApplicableCount, NotReviewedCount };
    public int[] CatOpenData => new[] { CatIOpen, CatIIOpen, CatIIIOpen };
    public int[] CatTotalData => new[] { CatITotal, CatIITotal, CatIIITotal };
}

/// <summary>
/// Per-benchmark compliance summary
/// </summary>
public class BenchmarkComplianceItem
{
    public int BenchmarkId { get; set; }
    public string BenchmarkName { get; set; } = string.Empty;
    public string Version { get; set; } = string.Empty;
    public int TotalRules { get; set; }
    public int OpenCount { get; set; }
    public int NotAFindingCount { get; set; }
    public int NotApplicableCount { get; set; }
    public int NotReviewedCount { get; set; }
    public int ChecklistCount { get; set; }

    public double CompliancePercentage => TotalRules > 0
        ? Math.Round((NotAFindingCount + NotApplicableCount) * 100.0 / TotalRules, 1)
        : 0;
}

/// <summary>
/// Site-level metrics summary
/// </summary>
public class SiteMetricsSummary
{
    public int SiteId { get; set; }
    public string SiteName { get; set; } = string.Empty;
    public string? Location { get; set; }

    // Host counts
    public int TotalHosts { get; set; }
    public int ActiveHosts { get; set; }

    // Vulnerability counts
    public int TotalVulnerabilities { get; set; }
    public int CriticalCount { get; set; }
    public int HighCount { get; set; }
    public int MediumCount { get; set; }
    public int LowCount { get; set; }
    public int InfoCount { get; set; }
    public int OpenVulnerabilities { get; set; }
    public int ExploitableCount { get; set; }

    // STIG counts
    public int StigChecklists { get; set; }
    public int StigOpenFindings { get; set; }
    public int StigNotAFinding { get; set; }
    public int StigNotApplicable { get; set; }
    public int StigNotReviewed { get; set; }
    public int StigTotalFindings { get; set; }

    // Calculated
    public double StigCompliancePercentage => StigTotalFindings > 0
        ? Math.Round((StigNotAFinding + StigNotApplicable) * 100.0 / StigTotalFindings, 1)
        : 0;

    public string RiskLevel
    {
        get
        {
            if (CriticalCount > 0) return "Critical";
            if (HighCount > 0) return "High";
            if (MediumCount > 0) return "Medium";
            if (LowCount > 0) return "Low";
            return "Minimal";
        }
    }
}

/// <summary>
/// Host-level metrics for drill-down
/// </summary>
public class HostMetricsSummary
{
    public int HostId { get; set; }
    public string HostName { get; set; } = string.Empty;
    public string? IPAddress { get; set; }
    public string? OperatingSystem { get; set; }
    public AssetType AssetType { get; set; }
    public HostStatus Status { get; set; }
    public DateTime? LastScanDate { get; set; }

    // Vulnerability counts
    public int TotalVulnerabilities { get; set; }
    public int CriticalCount { get; set; }
    public int HighCount { get; set; }
    public int MediumCount { get; set; }
    public int LowCount { get; set; }
    public int InfoCount { get; set; }
    public int OpenVulnerabilities { get; set; }
    public int ExploitableCount { get; set; }

    // STIG counts
    public int StigChecklists { get; set; }
    public int StigOpenFindings { get; set; }
    public int StigNotAFinding { get; set; }
    public int StigNotApplicable { get; set; }
    public int StigNotReviewed { get; set; }
    public int StigTotalFindings { get; set; }

    public double StigCompliancePercentage => StigTotalFindings > 0
        ? Math.Round((StigNotAFinding + StigNotApplicable) * 100.0 / StigTotalFindings, 1)
        : 0;

    public string RiskLevel
    {
        get
        {
            if (CriticalCount > 0) return "Critical";
            if (HighCount > 0) return "High";
            if (MediumCount > 0) return "Medium";
            if (LowCount > 0) return "Low";
            return "Minimal";
        }
    }
}

/// <summary>
/// Site detail view model (for drill-down)
/// </summary>
public class SiteDetailMetricsViewModel
{
    public int SiteId { get; set; }
    public string SiteName { get; set; } = string.Empty;
    public string? Location { get; set; }
    public string? OrganizationName { get; set; }
    public SiteMetricsSummary Summary { get; set; } = new();
    public List<HostMetricsSummary> Hosts { get; set; } = new();
    public VulnerabilityMetrics VulnerabilityMetrics { get; set; } = new();
    public StigComplianceMetrics StigMetrics { get; set; } = new();
}

/// <summary>
/// Generic chart data structure for JSON serialization
/// </summary>
public class ChartDataSet
{
    public string Label { get; set; } = string.Empty;
    public int[] Data { get; set; } = Array.Empty<int>();
    public string[] BackgroundColor { get; set; } = Array.Empty<string>();
    public string[] BorderColor { get; set; } = Array.Empty<string>();
    public int BorderWidth { get; set; } = 1;
}

public class ChartData
{
    public string[] Labels { get; set; } = Array.Empty<string>();
    public List<ChartDataSet> Datasets { get; set; } = new();
}
