using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using VulnMgmt.Web.Data;
using VulnMgmt.Web.Models.Domain;
using VulnMgmt.Web.Models.ViewModels;

namespace VulnMgmt.Web.Services;

public class NistComplianceExportService : INistComplianceExportService
{
    private readonly ApplicationDbContext _context;
    private readonly ILogger<NistComplianceExportService> _logger;

    public NistComplianceExportService(ApplicationDbContext context, ILogger<NistComplianceExportService> logger)
    {
        _context = context;
        _logger = logger;
    }

    public async Task<List<SiteSelectItem>> GetSitesForExportAsync()
    {
        return await _context.Sites
            .Where(s => s.IsActive)
            .Select(s => new SiteSelectItem
            {
                Id = s.Id,
                Name = s.Name,
                HostCount = s.Hosts.Count
            })
            .OrderBy(s => s.Name)
            .ToListAsync();
    }

    public async Task<NistExportPreview?> GetExportPreviewAsync(int siteId)
    {
        var site = await _context.Sites
            .Include(s => s.Hosts)
            .FirstOrDefaultAsync(s => s.Id == siteId);

        if (site == null) return null;

        var hostIds = site.Hosts.Select(h => h.Id).ToList();

        var stigChecklistCount = await _context.StigChecklists
            .Where(c => hostIds.Contains(c.HostId))
            .CountAsync();

        var stigResultCount = await _context.StigChecklistResults
            .Where(r => hostIds.Contains(r.Checklist.HostId))
            .CountAsync();

        var nessusVulnCount = await _context.HostVulnerabilities
            .Where(v => hostIds.Contains(v.HostId))
            .CountAsync();

        // Get unique CCIs from all STIG rules in checklists for this site
        var uniqueCcis = await _context.StigChecklistResults
            .Where(r => hostIds.Contains(r.Checklist.HostId))
            .Where(r => r.StigRule.CCIs != null && r.StigRule.CCIs != "")
            .Select(r => r.StigRule.CCIs)
            .Distinct()
            .ToListAsync();

        var cciSet = new HashSet<string>();
        foreach (var cciString in uniqueCcis.Where(c => c != null))
        {
            foreach (var cci in cciString!.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                cciSet.Add(cci);
            }
        }

        var lastScanDate = site.Hosts.Max(h => h.LastScanDate);

        return new NistExportPreview
        {
            SiteId = siteId,
            SiteName = site.Name,
            TotalHosts = site.Hosts.Count,
            TotalStigChecklists = stigChecklistCount,
            TotalStigRuleResults = stigResultCount,
            TotalNessusVulnerabilities = nessusVulnCount,
            UniqueCciCount = cciSet.Count,
            LastScanDate = lastScanDate
        };
    }

    public async Task<byte[]> ExportSiteToJsonAsync(int siteId, int? userId)
    {
        _logger.LogInformation("Starting NIST compliance export for site {SiteId}", siteId);

        // Load site
        var site = await _context.Sites
            .FirstOrDefaultAsync(s => s.Id == siteId)
            ?? throw new ArgumentException($"Site with ID {siteId} not found");

        // Load all hosts for the site
        var hosts = await _context.Hosts
            .Where(h => h.SiteId == siteId)
            .Include(h => h.Vulnerabilities)
            .OrderBy(h => h.DisplayName ?? h.DNSName ?? h.NetBIOSName)
            .ToListAsync();

        var hostIds = hosts.Select(h => h.Id).ToList();

        // Load all STIG checklists for hosts in this site
        var checklists = await _context.StigChecklists
            .Where(c => hostIds.Contains(c.HostId))
            .Include(c => c.BenchmarkVersion)
                .ThenInclude(v => v.StigBenchmark)
            .Include(c => c.Results)
                .ThenInclude(r => r.StigRule)
            .Include(c => c.Results)
                .ThenInclude(r => r.ModifiedBy)
            .Include(c => c.CreatedBy)
            .Include(c => c.LastModifiedBy)
            .ToListAsync();

        // Group checklists by host
        var checklistsByHost = checklists
            .GroupBy(c => c.HostId)
            .ToDictionary(g => g.Key, g => g.ToList());

        // Get user who is exporting
        string? exportedByUsername = null;
        if (userId.HasValue)
        {
            var user = await _context.Users.FindAsync(userId.Value);
            exportedByUsername = user?.DisplayName ?? user?.Username;
        }

        // Build the export object
        var export = new NistComplianceExport
        {
            ExportMetadata = new ExportMetadata
            {
                ExportDate = DateTime.UtcNow,
                ExportedBy = exportedByUsername
            },
            Site = BuildSiteExport(site),
            Hosts = new List<HostExport>()
        };

        // CCI aggregation data
        var cciData = new Dictionary<string, CciAggregation>();

        // Process each host
        foreach (var host in hosts)
        {
            var hostExport = BuildHostExport(host);

            // Add STIG checklists for this host
            if (checklistsByHost.TryGetValue(host.Id, out var hostChecklists))
            {
                foreach (var checklist in hostChecklists)
                {
                    var checklistExport = BuildChecklistExport(checklist, host, cciData);
                    hostExport.StigChecklists.Add(checklistExport);
                }
            }

            // Add Nessus vulnerabilities
            foreach (var vuln in host.Vulnerabilities)
            {
                hostExport.NessusVulnerabilities.Add(BuildVulnerabilityExport(vuln));
            }

            export.Hosts.Add(hostExport);
        }

        // Build CCI summary
        export.CciSummary = BuildCciSummary(cciData);

        // Calculate summary statistics
        export.Summary = BuildExportSummary(export);

        // Serialize to JSON
        var options = new JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
        };

        var json = JsonSerializer.Serialize(export, options);

        _logger.LogInformation("Completed NIST compliance export for site {SiteId}: {HostCount} hosts, {ChecklistCount} checklists, {VulnCount} vulnerabilities",
            siteId, export.Hosts.Count,
            export.Hosts.Sum(h => h.StigChecklists.Count),
            export.Hosts.Sum(h => h.NessusVulnerabilities.Count));

        return System.Text.Encoding.UTF8.GetBytes(json);
    }

    #region Private Helper Methods

    private static SiteExport BuildSiteExport(Site site)
    {
        return new SiteExport
        {
            Id = site.Id,
            Name = site.Name,
            Description = site.Description,
            Location = site.Location,
            OrganizationName = site.OrganizationName,
            IsActive = site.IsActive,
            CreatedDate = site.CreatedDate,
            ModifiedDate = site.ModifiedDate,
            Poc = new PointOfContact
            {
                Name = site.POCName,
                Email = site.POCEmail,
                Phone = site.POCPhone
            }
        };
    }

    private static HostExport BuildHostExport(Models.Domain.Host host)
    {
        return new HostExport
        {
            Id = host.Id,
            DnsName = host.DNSName,
            NetBIOSName = host.NetBIOSName,
            DisplayName = host.DisplayName,
            IpAddress = host.LastKnownIPAddress,
            MacAddress = host.LastKnownMACAddress,
            OperatingSystem = host.OperatingSystem,
            OsVersion = host.OSVersion,
            AssetType = host.AssetType,
            AssetTag = host.AssetTag,
            SerialNumber = host.SerialNumber,
            Status = host.Status,
            LastScanDate = host.LastScanDate,
            LastScanVulnCount = host.LastScanVulnCount,
            CreatedDate = host.CreatedDate,
            ModifiedDate = host.ModifiedDate
        };
    }

    private static StigChecklistExport BuildChecklistExport(StigChecklist checklist, Models.Domain.Host host, Dictionary<string, CciAggregation> cciData)
    {
        var checklistExport = new StigChecklistExport
        {
            Id = checklist.Id,
            Title = checklist.Title,
            Status = checklist.Status,
            ImportSource = checklist.ImportSource,
            CreatedDate = checklist.CreatedDate,
            LastModifiedDate = checklist.LastModifiedDate,
            CreatedBy = checklist.CreatedBy?.DisplayName ?? checklist.CreatedBy?.Username,
            LastModifiedBy = checklist.LastModifiedBy?.DisplayName ?? checklist.LastModifiedBy?.Username,
            BenchmarkInfo = new BenchmarkInfoExport
            {
                BenchmarkId = checklist.BenchmarkVersion.StigBenchmark.Id,
                BenchmarkVersionId = checklist.BenchmarkVersionId,
                StigId = checklist.BenchmarkVersion.StigBenchmark.StigId,
                Title = checklist.BenchmarkVersion.StigBenchmark.Title,
                Description = checklist.BenchmarkVersion.StigBenchmark.Description,
                Version = checklist.BenchmarkVersion.Version,
                Release = checklist.BenchmarkVersion.Release,
                ReleaseInfo = checklist.BenchmarkVersion.ReleaseInfo,
                BenchmarkDate = checklist.BenchmarkVersion.BenchmarkDate,
                RuleCount = checklist.BenchmarkVersion.RuleCount
            },
            Statistics = new ChecklistStatistics
            {
                TotalRules = checklist.Results.Count,
                NotReviewed = checklist.NotReviewedCount,
                Open = checklist.OpenCount,
                NotAFinding = checklist.NotAFindingCount,
                NotApplicable = checklist.NotApplicableCount
            }
        };

        // Process results and aggregate CCI data
        foreach (var result in checklist.Results.OrderBy(r => r.StigRule.VulnId))
        {
            var ccis = ParseCcis(result.StigRule.CCIs);

            var resultExport = new StigResultExport
            {
                VulnId = result.StigRule.VulnId,
                RuleId = result.StigRule.RuleId,
                GroupId = result.StigRule.GroupId,
                GroupTitle = result.StigRule.GroupTitle,
                RuleVersion = result.StigRule.RuleVersion,
                RuleTitle = result.StigRule.RuleTitle,
                Severity = result.StigRule.Severity,
                SeverityOverride = result.SeverityOverride,
                SeverityOverrideJustification = result.SeverityOverrideJustification,
                Status = result.Status,
                FindingDetails = result.FindingDetails,
                Comments = result.Comments,
                Ccis = ccis,
                LegacyIds = result.StigRule.LegacyIds,
                Discussion = result.StigRule.Discussion,
                CheckContent = result.StigRule.CheckContent,
                FixText = result.StigRule.FixText,
                LastModifiedDate = result.LastModifiedDate,
                ModifiedBy = result.ModifiedBy?.DisplayName ?? result.ModifiedBy?.Username
            };

            checklistExport.Results.Add(resultExport);

            // Aggregate CCI data
            var hostName = host.DisplayName ?? host.DNSName ?? host.NetBIOSName ?? $"Host-{host.Id}";
            foreach (var cci in ccis)
            {
                if (!cciData.TryGetValue(cci, out var agg))
                {
                    agg = new CciAggregation { CciId = cci };
                    cciData[cci] = agg;
                }

                agg.TotalRuleCount++;
                agg.AffectedHosts.Add(hostName);
                agg.AffectedVulnIds.Add(result.StigRule.VulnId);

                switch (result.Status)
                {
                    case StigResultStatus.Open:
                        agg.OpenFindingCount++;
                        break;
                    case StigResultStatus.NotAFinding:
                        agg.NotAFindingCount++;
                        break;
                    case StigResultStatus.NotApplicable:
                        agg.NotApplicableCount++;
                        break;
                    case StigResultStatus.NotReviewed:
                        agg.NotReviewedCount++;
                        break;
                }
            }
        }

        return checklistExport;
    }

    private static NessusVulnerabilityExport BuildVulnerabilityExport(HostVulnerability vuln)
    {
        return new NessusVulnerabilityExport
        {
            Id = vuln.Id,
            PluginId = vuln.PluginId,
            PluginName = vuln.PluginName,
            Family = vuln.Family,
            Severity = vuln.Severity,
            IpAddress = vuln.IPAddress,
            Protocol = vuln.Protocol,
            Port = vuln.Port,
            MacAddress = vuln.MACAddress,
            Cve = vuln.CVE,
            VulnPublicationDate = vuln.VulnPublicationDate,
            Synopsis = vuln.Synopsis,
            Description = vuln.Description,
            Solution = vuln.Solution,
            SeeAlso = vuln.SeeAlso,
            PluginText = vuln.PluginText,
            IsExploitable = vuln.IsExploitable,
            ExploitFrameworks = vuln.ExploitFrameworks,
            ExploitEase = vuln.ExploitEase,
            FirstDiscovered = vuln.FirstDiscovered,
            LastObserved = vuln.LastObserved,
            RemediationStatus = vuln.RemediationStatus,
            RemediationNotes = vuln.RemediationNotes,
            RemediationDate = vuln.RemediationDate,
            ImportSource = vuln.ImportSource
        };
    }

    private static List<CciSummaryItem> BuildCciSummary(Dictionary<string, CciAggregation> cciData)
    {
        return cciData.Values
            .OrderBy(c => c.CciId)
            .Select(c => new CciSummaryItem
            {
                CciId = c.CciId,
                TotalRuleCount = c.TotalRuleCount,
                OpenFindingCount = c.OpenFindingCount,
                NotAFindingCount = c.NotAFindingCount,
                NotApplicableCount = c.NotApplicableCount,
                NotReviewedCount = c.NotReviewedCount,
                AffectedHosts = c.AffectedHosts.Distinct().OrderBy(h => h).ToList(),
                AffectedVulnIds = c.AffectedVulnIds.Distinct().OrderBy(v => v).ToList()
            })
            .ToList();
    }

    private static ExportSummary BuildExportSummary(NistComplianceExport export)
    {
        var summary = new ExportSummary
        {
            TotalHosts = export.Hosts.Count
        };

        // STIG summary
        var allStigResults = export.Hosts
            .SelectMany(h => h.StigChecklists)
            .SelectMany(c => c.Results)
            .ToList();

        summary.StigChecklists = new StigChecklistSummary
        {
            TotalChecklists = export.Hosts.Sum(h => h.StigChecklists.Count),
            TotalRuleResults = allStigResults.Count,
            Open = allStigResults.Count(r => r.Status == StigResultStatus.Open),
            NotAFinding = allStigResults.Count(r => r.Status == StigResultStatus.NotAFinding),
            NotApplicable = allStigResults.Count(r => r.Status == StigResultStatus.NotApplicable),
            NotReviewed = allStigResults.Count(r => r.Status == StigResultStatus.NotReviewed)
        };

        // Nessus summary
        var allVulns = export.Hosts
            .SelectMany(h => h.NessusVulnerabilities)
            .ToList();

        summary.NessusVulnerabilities = new NessusVulnerabilitySummary
        {
            Total = allVulns.Count,
            Critical = allVulns.Count(v => v.Severity == Severity.Critical),
            High = allVulns.Count(v => v.Severity == Severity.High),
            Medium = allVulns.Count(v => v.Severity == Severity.Medium),
            Low = allVulns.Count(v => v.Severity == Severity.Low),
            Info = allVulns.Count(v => v.Severity == Severity.Info),
            Exploitable = allVulns.Count(v => v.IsExploitable),
            ByRemediationStatus = new RemediationStatusSummary
            {
                Open = allVulns.Count(v => v.RemediationStatus == RemediationStatus.Open),
                InProgress = allVulns.Count(v => v.RemediationStatus == RemediationStatus.InProgress),
                Remediated = allVulns.Count(v => v.RemediationStatus == RemediationStatus.Remediated),
                Accepted = allVulns.Count(v => v.RemediationStatus == RemediationStatus.Accepted),
                FalsePositive = allVulns.Count(v => v.RemediationStatus == RemediationStatus.FalsePositive)
            }
        };

        // CCI coverage
        summary.CciCoverage = new CciCoverageSummary
        {
            TotalUniqueCcis = export.CciSummary.Count,
            CcisWithOpenFindings = export.CciSummary.Count(c => c.OpenFindingCount > 0)
        };

        return summary;
    }

    private static List<string> ParseCcis(string? cciString)
    {
        if (string.IsNullOrWhiteSpace(cciString))
            return new List<string>();

        return cciString
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .ToList();
    }

    #endregion

    #region Helper Classes

    private class CciAggregation
    {
        public string CciId { get; set; } = string.Empty;
        public int TotalRuleCount { get; set; }
        public int OpenFindingCount { get; set; }
        public int NotAFindingCount { get; set; }
        public int NotApplicableCount { get; set; }
        public int NotReviewedCount { get; set; }
        public HashSet<string> AffectedHosts { get; set; } = new();
        public HashSet<string> AffectedVulnIds { get; set; } = new();
    }

    #endregion
}
