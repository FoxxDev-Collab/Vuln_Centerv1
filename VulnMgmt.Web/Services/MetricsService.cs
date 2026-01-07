using Microsoft.EntityFrameworkCore;
using VulnMgmt.Web.Data;
using VulnMgmt.Web.Models.Domain;
using VulnMgmt.Web.Models.ViewModels;

namespace VulnMgmt.Web.Services;

public class MetricsService : IMetricsService
{
    private readonly ApplicationDbContext _context;
    private readonly ILogger<MetricsService> _logger;

    public MetricsService(ApplicationDbContext context, ILogger<MetricsService> logger)
    {
        _context = context;
        _logger = logger;
    }

    public async Task<AtoMetricsDashboardViewModel> GetDashboardMetricsAsync()
    {
        var dashboard = new AtoMetricsDashboardViewModel
        {
            PackageOverview = await GetPackageOverviewAsync(),
            VulnerabilityMetrics = await GetVulnerabilityMetricsAsync(),
            StigMetrics = await GetStigComplianceMetricsAsync(),
            SiteBreakdown = await GetSiteBreakdownAsync(),
            GeneratedAt = DateTime.Now
        };

        return dashboard;
    }

    public async Task<AtoPackageOverview> GetPackageOverviewAsync()
    {
        var overview = new AtoPackageOverview();

        // Site and host counts
        overview.TotalSites = await _context.Sites.CountAsync(s => s.IsActive);
        overview.TotalHosts = await _context.Hosts.CountAsync();
        overview.ActiveHosts = await _context.Hosts.CountAsync(h => h.Status == HostStatus.Active);

        // Vulnerability counts
        var vulnQuery = _context.HostVulnerabilities.AsQueryable();
        overview.TotalVulnerabilities = await vulnQuery.CountAsync();
        overview.OpenVulnerabilities = await vulnQuery.CountAsync(v => v.RemediationStatus == RemediationStatus.Open);
        overview.CriticalVulnerabilities = await vulnQuery.CountAsync(v => v.Severity == Severity.Critical && v.RemediationStatus == RemediationStatus.Open);
        overview.HighVulnerabilities = await vulnQuery.CountAsync(v => v.Severity == Severity.High && v.RemediationStatus == RemediationStatus.Open);
        overview.ExploitableVulnerabilities = await vulnQuery.CountAsync(v => v.IsExploitable && v.RemediationStatus == RemediationStatus.Open);

        // STIG counts
        overview.TotalStigChecklists = await _context.StigChecklists.CountAsync();

        var stigResults = await _context.StigChecklistResults
            .GroupBy(r => r.Status)
            .Select(g => new { Status = g.Key, Count = g.Count() })
            .ToListAsync();

        overview.TotalStigFindings = stigResults.Sum(r => r.Count);
        overview.StigOpenFindings = stigResults.FirstOrDefault(r => r.Status == StigResultStatus.Open)?.Count ?? 0;
        overview.StigNotAFinding = stigResults.FirstOrDefault(r => r.Status == StigResultStatus.NotAFinding)?.Count ?? 0;
        overview.StigNotApplicable = stigResults.FirstOrDefault(r => r.Status == StigResultStatus.NotApplicable)?.Count ?? 0;
        overview.StigNotReviewed = stigResults.FirstOrDefault(r => r.Status == StigResultStatus.NotReviewed)?.Count ?? 0;

        // Calculate compliance percentage
        var totalEvaluated = overview.StigNotAFinding + overview.StigNotApplicable + overview.StigOpenFindings;
        overview.OverallCompliancePercentage = totalEvaluated > 0
            ? Math.Round((overview.StigNotAFinding + overview.StigNotApplicable) * 100.0 / totalEvaluated, 1)
            : 0;

        // Calculate risk score (0-100, higher = worse)
        // Based on weighted vulnerability counts
        var riskScore = 0.0;
        if (overview.TotalHosts > 0)
        {
            var criticalWeight = overview.CriticalVulnerabilities * 10.0;
            var highWeight = overview.HighVulnerabilities * 5.0;
            var exploitableBonus = overview.ExploitableVulnerabilities * 3.0;
            riskScore = Math.Min(100, (criticalWeight + highWeight + exploitableBonus) / overview.TotalHosts);
        }
        overview.VulnerabilityRiskScore = Math.Round(riskScore, 1);

        return overview;
    }

    public async Task<VulnerabilityMetrics> GetVulnerabilityMetricsAsync(int? siteId = null)
    {
        var metrics = new VulnerabilityMetrics();

        var query = _context.HostVulnerabilities
            .Include(v => v.Host)
            .AsQueryable();

        if (siteId.HasValue)
        {
            query = query.Where(v => v.Host.SiteId == siteId.Value);
        }

        // By severity
        var severityCounts = await query
            .GroupBy(v => v.Severity)
            .Select(g => new { Severity = g.Key, Count = g.Count() })
            .ToListAsync();

        metrics.CriticalCount = severityCounts.FirstOrDefault(s => s.Severity == Severity.Critical)?.Count ?? 0;
        metrics.HighCount = severityCounts.FirstOrDefault(s => s.Severity == Severity.High)?.Count ?? 0;
        metrics.MediumCount = severityCounts.FirstOrDefault(s => s.Severity == Severity.Medium)?.Count ?? 0;
        metrics.LowCount = severityCounts.FirstOrDefault(s => s.Severity == Severity.Low)?.Count ?? 0;
        metrics.InfoCount = severityCounts.FirstOrDefault(s => s.Severity == Severity.Info)?.Count ?? 0;

        // By status
        var statusCounts = await query
            .GroupBy(v => v.RemediationStatus)
            .Select(g => new { Status = g.Key, Count = g.Count() })
            .ToListAsync();

        metrics.OpenCount = statusCounts.FirstOrDefault(s => s.Status == RemediationStatus.Open)?.Count ?? 0;
        metrics.InProgressCount = statusCounts.FirstOrDefault(s => s.Status == RemediationStatus.InProgress)?.Count ?? 0;
        metrics.RemediatedCount = statusCounts.FirstOrDefault(s => s.Status == RemediationStatus.Remediated)?.Count ?? 0;
        metrics.AcceptedCount = statusCounts.FirstOrDefault(s => s.Status == RemediationStatus.Accepted)?.Count ?? 0;
        metrics.FalsePositiveCount = statusCounts.FirstOrDefault(s => s.Status == RemediationStatus.FalsePositive)?.Count ?? 0;

        // Additional counts
        metrics.ExploitableCount = await query.CountAsync(v => v.IsExploitable);
        metrics.UniquePluginCount = await query.Select(v => v.PluginId).Distinct().CountAsync();
        metrics.UniqueCveCount = await query.Where(v => v.CVE != null).Select(v => v.CVE).Distinct().CountAsync();

        // Top vulnerabilities
        metrics.TopVulnerabilities = await query
            .Where(v => v.RemediationStatus == RemediationStatus.Open)
            .GroupBy(v => new { v.PluginId, v.PluginName, v.Severity, v.IsExploitable, v.CVE })
            .Select(g => new TopVulnerabilityItem
            {
                PluginId = g.Key.PluginId,
                PluginName = g.Key.PluginName,
                Severity = g.Key.Severity,
                IsExploitable = g.Key.IsExploitable,
                CVE = g.Key.CVE,
                AffectedHostCount = g.Select(v => v.HostId).Distinct().Count()
            })
            .OrderByDescending(v => v.Severity)
            .ThenByDescending(v => v.AffectedHostCount)
            .Take(10)
            .ToListAsync();

        return metrics;
    }

    public async Task<StigComplianceMetrics> GetStigComplianceMetricsAsync(int? siteId = null)
    {
        var metrics = new StigComplianceMetrics();

        var resultsQuery = _context.StigChecklistResults
            .Include(r => r.Checklist)
                .ThenInclude(c => c.Host)
            .Include(r => r.StigRule)
            .AsQueryable();

        if (siteId.HasValue)
        {
            resultsQuery = resultsQuery.Where(r => r.Checklist.Host.SiteId == siteId.Value);
        }

        // Status counts
        var statusCounts = await resultsQuery
            .GroupBy(r => r.Status)
            .Select(g => new { Status = g.Key, Count = g.Count() })
            .ToListAsync();

        metrics.TotalRulesEvaluated = statusCounts.Sum(s => s.Count);
        metrics.OpenCount = statusCounts.FirstOrDefault(s => s.Status == StigResultStatus.Open)?.Count ?? 0;
        metrics.NotAFindingCount = statusCounts.FirstOrDefault(s => s.Status == StigResultStatus.NotAFinding)?.Count ?? 0;
        metrics.NotApplicableCount = statusCounts.FirstOrDefault(s => s.Status == StigResultStatus.NotApplicable)?.Count ?? 0;
        metrics.NotReviewedCount = statusCounts.FirstOrDefault(s => s.Status == StigResultStatus.NotReviewed)?.Count ?? 0;

        // CAT level counts
        var catCounts = await resultsQuery
            .GroupBy(r => new { r.StigRule.Severity, r.Status })
            .Select(g => new { g.Key.Severity, g.Key.Status, Count = g.Count() })
            .ToListAsync();

        metrics.CatITotal = catCounts.Where(c => c.Severity == StigSeverity.High).Sum(c => c.Count);
        metrics.CatIOpen = catCounts.Where(c => c.Severity == StigSeverity.High && c.Status == StigResultStatus.Open).Sum(c => c.Count);
        metrics.CatIITotal = catCounts.Where(c => c.Severity == StigSeverity.Medium).Sum(c => c.Count);
        metrics.CatIIOpen = catCounts.Where(c => c.Severity == StigSeverity.Medium && c.Status == StigResultStatus.Open).Sum(c => c.Count);
        metrics.CatIIITotal = catCounts.Where(c => c.Severity == StigSeverity.Low).Sum(c => c.Count);
        metrics.CatIIIOpen = catCounts.Where(c => c.Severity == StigSeverity.Low && c.Status == StigResultStatus.Open).Sum(c => c.Count);

        // Per-benchmark compliance
        metrics.BenchmarkCompliance = await _context.StigChecklists
            .Include(c => c.BenchmarkVersion)
                .ThenInclude(v => v.StigBenchmark)
            .Include(c => c.Results)
            .Where(c => !siteId.HasValue || c.Host.SiteId == siteId.Value)
            .GroupBy(c => new { c.BenchmarkVersion.StigBenchmark.Id, c.BenchmarkVersion.StigBenchmark.Title, c.BenchmarkVersion.Version })
            .Select(g => new BenchmarkComplianceItem
            {
                BenchmarkId = g.Key.Id,
                BenchmarkName = g.Key.Title,
                Version = g.Key.Version,
                ChecklistCount = g.Count(),
                TotalRules = g.SelectMany(c => c.Results).Count(),
                OpenCount = g.SelectMany(c => c.Results).Count(r => r.Status == StigResultStatus.Open),
                NotAFindingCount = g.SelectMany(c => c.Results).Count(r => r.Status == StigResultStatus.NotAFinding),
                NotApplicableCount = g.SelectMany(c => c.Results).Count(r => r.Status == StigResultStatus.NotApplicable),
                NotReviewedCount = g.SelectMany(c => c.Results).Count(r => r.Status == StigResultStatus.NotReviewed)
            })
            .OrderByDescending(b => b.ChecklistCount)
            .ToListAsync();

        return metrics;
    }

    public async Task<List<SiteMetricsSummary>> GetSiteBreakdownAsync()
    {
        var sites = await _context.Sites
            .Where(s => s.IsActive)
            .Include(s => s.Hosts)
                .ThenInclude(h => h.Vulnerabilities)
            .ToListAsync();

        var siteMetrics = new List<SiteMetricsSummary>();

        foreach (var site in sites)
        {
            var summary = new SiteMetricsSummary
            {
                SiteId = site.Id,
                SiteName = site.Name,
                Location = site.Location,
                TotalHosts = site.Hosts.Count,
                ActiveHosts = site.Hosts.Count(h => h.Status == HostStatus.Active)
            };

            // Vulnerability counts
            var vulns = site.Hosts.SelectMany(h => h.Vulnerabilities).ToList();
            summary.TotalVulnerabilities = vulns.Count;
            summary.CriticalCount = vulns.Count(v => v.Severity == Severity.Critical && v.RemediationStatus == RemediationStatus.Open);
            summary.HighCount = vulns.Count(v => v.Severity == Severity.High && v.RemediationStatus == RemediationStatus.Open);
            summary.MediumCount = vulns.Count(v => v.Severity == Severity.Medium && v.RemediationStatus == RemediationStatus.Open);
            summary.LowCount = vulns.Count(v => v.Severity == Severity.Low && v.RemediationStatus == RemediationStatus.Open);
            summary.InfoCount = vulns.Count(v => v.Severity == Severity.Info && v.RemediationStatus == RemediationStatus.Open);
            summary.OpenVulnerabilities = vulns.Count(v => v.RemediationStatus == RemediationStatus.Open);
            summary.ExploitableCount = vulns.Count(v => v.IsExploitable && v.RemediationStatus == RemediationStatus.Open);

            // STIG counts - need separate query due to navigation properties
            var hostIds = site.Hosts.Select(h => h.Id).ToList();
            var stigResults = await _context.StigChecklistResults
                .Include(r => r.Checklist)
                .Where(r => hostIds.Contains(r.Checklist.HostId))
                .GroupBy(r => r.Status)
                .Select(g => new { Status = g.Key, Count = g.Count() })
                .ToListAsync();

            summary.StigChecklists = await _context.StigChecklists
                .CountAsync(c => hostIds.Contains(c.HostId));

            summary.StigTotalFindings = stigResults.Sum(r => r.Count);
            summary.StigOpenFindings = stigResults.FirstOrDefault(r => r.Status == StigResultStatus.Open)?.Count ?? 0;
            summary.StigNotAFinding = stigResults.FirstOrDefault(r => r.Status == StigResultStatus.NotAFinding)?.Count ?? 0;
            summary.StigNotApplicable = stigResults.FirstOrDefault(r => r.Status == StigResultStatus.NotApplicable)?.Count ?? 0;
            summary.StigNotReviewed = stigResults.FirstOrDefault(r => r.Status == StigResultStatus.NotReviewed)?.Count ?? 0;

            siteMetrics.Add(summary);
        }

        return siteMetrics.OrderByDescending(s => s.CriticalCount + s.HighCount).ToList();
    }

    public async Task<SiteDetailMetricsViewModel?> GetSiteMetricsAsync(int siteId)
    {
        var site = await _context.Sites
            .FirstOrDefaultAsync(s => s.Id == siteId);

        if (site == null) return null;

        var siteBreakdown = await GetSiteBreakdownAsync();
        var summary = siteBreakdown.FirstOrDefault(s => s.SiteId == siteId) ?? new SiteMetricsSummary();

        return new SiteDetailMetricsViewModel
        {
            SiteId = site.Id,
            SiteName = site.Name,
            Location = site.Location,
            OrganizationName = site.OrganizationName,
            Summary = summary,
            Hosts = await GetHostMetricsForSiteAsync(siteId),
            VulnerabilityMetrics = await GetVulnerabilityMetricsAsync(siteId),
            StigMetrics = await GetStigComplianceMetricsAsync(siteId)
        };
    }

    public async Task<List<HostMetricsSummary>> GetHostMetricsForSiteAsync(int siteId)
    {
        var hosts = await _context.Hosts
            .Where(h => h.SiteId == siteId)
            .Include(h => h.Vulnerabilities)
            .ToListAsync();

        var hostMetrics = new List<HostMetricsSummary>();

        foreach (var host in hosts)
        {
            var metrics = new HostMetricsSummary
            {
                HostId = host.Id,
                HostName = host.DisplayName ?? host.DNSName ?? host.NetBIOSName ?? $"Host {host.Id}",
                IPAddress = host.LastKnownIPAddress,
                OperatingSystem = host.OperatingSystem,
                AssetType = host.AssetType,
                Status = host.Status,
                LastScanDate = host.LastScanDate
            };

            // Vulnerability counts
            var vulns = host.Vulnerabilities;
            metrics.TotalVulnerabilities = vulns.Count;
            metrics.CriticalCount = vulns.Count(v => v.Severity == Severity.Critical && v.RemediationStatus == RemediationStatus.Open);
            metrics.HighCount = vulns.Count(v => v.Severity == Severity.High && v.RemediationStatus == RemediationStatus.Open);
            metrics.MediumCount = vulns.Count(v => v.Severity == Severity.Medium && v.RemediationStatus == RemediationStatus.Open);
            metrics.LowCount = vulns.Count(v => v.Severity == Severity.Low && v.RemediationStatus == RemediationStatus.Open);
            metrics.InfoCount = vulns.Count(v => v.Severity == Severity.Info && v.RemediationStatus == RemediationStatus.Open);
            metrics.OpenVulnerabilities = vulns.Count(v => v.RemediationStatus == RemediationStatus.Open);
            metrics.ExploitableCount = vulns.Count(v => v.IsExploitable && v.RemediationStatus == RemediationStatus.Open);

            // STIG counts
            var stigResults = await _context.StigChecklistResults
                .Include(r => r.Checklist)
                .Where(r => r.Checklist.HostId == host.Id)
                .GroupBy(r => r.Status)
                .Select(g => new { Status = g.Key, Count = g.Count() })
                .ToListAsync();

            metrics.StigChecklists = await _context.StigChecklists.CountAsync(c => c.HostId == host.Id);
            metrics.StigTotalFindings = stigResults.Sum(r => r.Count);
            metrics.StigOpenFindings = stigResults.FirstOrDefault(r => r.Status == StigResultStatus.Open)?.Count ?? 0;
            metrics.StigNotAFinding = stigResults.FirstOrDefault(r => r.Status == StigResultStatus.NotAFinding)?.Count ?? 0;
            metrics.StigNotApplicable = stigResults.FirstOrDefault(r => r.Status == StigResultStatus.NotApplicable)?.Count ?? 0;
            metrics.StigNotReviewed = stigResults.FirstOrDefault(r => r.Status == StigResultStatus.NotReviewed)?.Count ?? 0;

            hostMetrics.Add(metrics);
        }

        return hostMetrics.OrderByDescending(h => h.CriticalCount + h.HighCount).ToList();
    }

    public async Task<HostMetricsSummary?> GetHostMetricsAsync(int hostId)
    {
        var host = await _context.Hosts
            .Include(h => h.Vulnerabilities)
            .FirstOrDefaultAsync(h => h.Id == hostId);

        if (host == null) return null;

        var metrics = new HostMetricsSummary
        {
            HostId = host.Id,
            HostName = host.DisplayName ?? host.DNSName ?? host.NetBIOSName ?? $"Host {host.Id}",
            IPAddress = host.LastKnownIPAddress,
            OperatingSystem = host.OperatingSystem,
            AssetType = host.AssetType,
            Status = host.Status,
            LastScanDate = host.LastScanDate
        };

        // Vulnerability counts
        var vulns = host.Vulnerabilities;
        metrics.TotalVulnerabilities = vulns.Count;
        metrics.CriticalCount = vulns.Count(v => v.Severity == Severity.Critical && v.RemediationStatus == RemediationStatus.Open);
        metrics.HighCount = vulns.Count(v => v.Severity == Severity.High && v.RemediationStatus == RemediationStatus.Open);
        metrics.MediumCount = vulns.Count(v => v.Severity == Severity.Medium && v.RemediationStatus == RemediationStatus.Open);
        metrics.LowCount = vulns.Count(v => v.Severity == Severity.Low && v.RemediationStatus == RemediationStatus.Open);
        metrics.InfoCount = vulns.Count(v => v.Severity == Severity.Info && v.RemediationStatus == RemediationStatus.Open);
        metrics.OpenVulnerabilities = vulns.Count(v => v.RemediationStatus == RemediationStatus.Open);
        metrics.ExploitableCount = vulns.Count(v => v.IsExploitable && v.RemediationStatus == RemediationStatus.Open);

        // STIG counts
        var stigResults = await _context.StigChecklistResults
            .Include(r => r.Checklist)
            .Where(r => r.Checklist.HostId == host.Id)
            .GroupBy(r => r.Status)
            .Select(g => new { Status = g.Key, Count = g.Count() })
            .ToListAsync();

        metrics.StigChecklists = await _context.StigChecklists.CountAsync(c => c.HostId == host.Id);
        metrics.StigTotalFindings = stigResults.Sum(r => r.Count);
        metrics.StigOpenFindings = stigResults.FirstOrDefault(r => r.Status == StigResultStatus.Open)?.Count ?? 0;
        metrics.StigNotAFinding = stigResults.FirstOrDefault(r => r.Status == StigResultStatus.NotAFinding)?.Count ?? 0;
        metrics.StigNotApplicable = stigResults.FirstOrDefault(r => r.Status == StigResultStatus.NotApplicable)?.Count ?? 0;
        metrics.StigNotReviewed = stigResults.FirstOrDefault(r => r.Status == StigResultStatus.NotReviewed)?.Count ?? 0;

        return metrics;
    }
}
