using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using VulnMgmt.Web.Services;

namespace VulnMgmt.Web.Controllers;

[Authorize(Policy = "CanView")]
public class MetricsController : Controller
{
    private readonly IMetricsService _metricsService;
    private readonly ILogger<MetricsController> _logger;

    public MetricsController(IMetricsService metricsService, ILogger<MetricsController> logger)
    {
        _metricsService = metricsService;
        _logger = logger;
    }

    // GET: Metrics
    public async Task<IActionResult> Index()
    {
        var dashboard = await _metricsService.GetDashboardMetricsAsync();
        return View(dashboard);
    }

    // GET: Metrics/Site/5
    [Route("Metrics/Site/{id}")]
    public async Task<IActionResult> Site(int id)
    {
        var siteMetrics = await _metricsService.GetSiteMetricsAsync(id);
        if (siteMetrics == null)
        {
            return NotFound();
        }
        return View(siteMetrics);
    }

    // AJAX: Get site metrics data for charts
    [HttpGet]
    public async Task<IActionResult> GetSiteData(int siteId)
    {
        var siteMetrics = await _metricsService.GetSiteMetricsAsync(siteId);
        if (siteMetrics == null)
        {
            return NotFound();
        }

        return Json(new
        {
            summary = siteMetrics.Summary,
            vulnerabilityMetrics = new
            {
                severityData = siteMetrics.VulnerabilityMetrics.SeverityData,
                statusData = siteMetrics.VulnerabilityMetrics.StatusData,
                exploitableCount = siteMetrics.VulnerabilityMetrics.ExploitableCount
            },
            stigMetrics = new
            {
                statusData = siteMetrics.StigMetrics.StatusData,
                compliancePercentage = siteMetrics.StigMetrics.CompliancePercentage,
                catOpenData = siteMetrics.StigMetrics.CatOpenData
            }
        });
    }

    // AJAX: Get host list for a site
    [HttpGet]
    public async Task<IActionResult> GetHostsForSite(int siteId)
    {
        var hosts = await _metricsService.GetHostMetricsForSiteAsync(siteId);
        return Json(hosts);
    }

    // AJAX: Get host metrics
    [HttpGet]
    public async Task<IActionResult> GetHostData(int hostId)
    {
        var hostMetrics = await _metricsService.GetHostMetricsAsync(hostId);
        if (hostMetrics == null)
        {
            return NotFound();
        }
        return Json(hostMetrics);
    }

    // GET: Metrics/RefreshDashboard (AJAX partial refresh)
    [HttpGet]
    public async Task<IActionResult> RefreshDashboard()
    {
        var dashboard = await _metricsService.GetDashboardMetricsAsync();
        return Json(new
        {
            overview = dashboard.PackageOverview,
            vulnerabilityMetrics = new
            {
                severityData = dashboard.VulnerabilityMetrics.SeverityData,
                statusData = dashboard.VulnerabilityMetrics.StatusData,
                topVulnerabilities = dashboard.VulnerabilityMetrics.TopVulnerabilities
            },
            stigMetrics = new
            {
                statusData = dashboard.StigMetrics.StatusData,
                compliancePercentage = dashboard.StigMetrics.CompliancePercentage,
                catOpenData = dashboard.StigMetrics.CatOpenData,
                benchmarkCompliance = dashboard.StigMetrics.BenchmarkCompliance
            },
            siteBreakdown = dashboard.SiteBreakdown,
            generatedAt = dashboard.GeneratedAt.ToString("g")
        });
    }
}
