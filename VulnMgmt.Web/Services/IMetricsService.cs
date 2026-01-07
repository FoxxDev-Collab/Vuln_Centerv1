using VulnMgmt.Web.Models.ViewModels;

namespace VulnMgmt.Web.Services;

/// <summary>
/// Service for generating ATO package metrics and analytics
/// </summary>
public interface IMetricsService
{
    /// <summary>
    /// Gets the complete ATO metrics dashboard data
    /// </summary>
    Task<AtoMetricsDashboardViewModel> GetDashboardMetricsAsync();

    /// <summary>
    /// Gets detailed metrics for a specific site
    /// </summary>
    Task<SiteDetailMetricsViewModel?> GetSiteMetricsAsync(int siteId);

    /// <summary>
    /// Gets metrics for all hosts in a site
    /// </summary>
    Task<List<HostMetricsSummary>> GetHostMetricsForSiteAsync(int siteId);

    /// <summary>
    /// Gets detailed metrics for a specific host
    /// </summary>
    Task<HostMetricsSummary?> GetHostMetricsAsync(int hostId);

    /// <summary>
    /// Gets package overview statistics
    /// </summary>
    Task<AtoPackageOverview> GetPackageOverviewAsync();

    /// <summary>
    /// Gets vulnerability metrics
    /// </summary>
    Task<VulnerabilityMetrics> GetVulnerabilityMetricsAsync(int? siteId = null);

    /// <summary>
    /// Gets STIG compliance metrics
    /// </summary>
    Task<StigComplianceMetrics> GetStigComplianceMetricsAsync(int? siteId = null);

    /// <summary>
    /// Gets site breakdown metrics
    /// </summary>
    Task<List<SiteMetricsSummary>> GetSiteBreakdownAsync();
}
