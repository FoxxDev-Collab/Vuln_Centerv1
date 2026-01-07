using System.Globalization;
using System.Text;
using ClosedXML.Excel;
using CsvHelper;
using Microsoft.EntityFrameworkCore;
using VulnMgmt.Web.Data;
using VulnMgmt.Web.Models.Domain;

namespace VulnMgmt.Web.Services;

public class ReportService : IReportService
{
    private readonly ApplicationDbContext _context;
    private readonly ILogger<ReportService> _logger;

    public ReportService(ApplicationDbContext context, ILogger<ReportService> logger)
    {
        _context = context;
        _logger = logger;
    }

    public async Task<byte[]> ExportVulnerabilitiesToCsvAsync(VulnerabilityExportCriteria criteria)
    {
        var vulnerabilities = await GetFilteredVulnerabilitiesAsync(criteria);

        using var memoryStream = new MemoryStream();
        using var writer = new StreamWriter(memoryStream, Encoding.UTF8);
        using var csv = new CsvWriter(writer, CultureInfo.InvariantCulture);

        // Write headers
        csv.WriteField("Plugin ID");
        csv.WriteField("Plugin Name");
        csv.WriteField("Severity");
        csv.WriteField("Host");
        csv.WriteField("IP Address");
        csv.WriteField("Port");
        csv.WriteField("Protocol");
        csv.WriteField("CVE");
        csv.WriteField("Synopsis");
        csv.WriteField("Solution");
        csv.WriteField("Exploitable");
        csv.WriteField("Status");
        csv.WriteField("First Discovered");
        csv.WriteField("Last Observed");
        csv.WriteField("Site");
        await csv.NextRecordAsync();

        foreach (var vuln in vulnerabilities)
        {
            csv.WriteField(vuln.PluginId);
            csv.WriteField(vuln.PluginName);
            csv.WriteField(vuln.Severity.ToString());
            csv.WriteField(vuln.Host?.DisplayName ?? vuln.Host?.DNSName ?? vuln.Host?.NetBIOSName);
            csv.WriteField(vuln.IPAddress ?? vuln.Host?.LastKnownIPAddress);
            csv.WriteField(vuln.Port);
            csv.WriteField(vuln.Protocol);
            csv.WriteField(vuln.CVE);
            csv.WriteField(vuln.Synopsis);
            csv.WriteField(vuln.Solution);
            csv.WriteField(vuln.IsExploitable ? "Yes" : "No");
            csv.WriteField(vuln.RemediationStatus.ToString());
            csv.WriteField(vuln.FirstDiscovered?.ToString("yyyy-MM-dd"));
            csv.WriteField(vuln.LastObserved?.ToString("yyyy-MM-dd"));
            csv.WriteField(vuln.Host?.Site?.Name);
            await csv.NextRecordAsync();
        }

        await writer.FlushAsync();
        return memoryStream.ToArray();
    }

    public async Task<byte[]> ExportVulnerabilitiesToExcelAsync(VulnerabilityExportCriteria criteria)
    {
        var vulnerabilities = await GetFilteredVulnerabilitiesAsync(criteria);

        using var workbook = new XLWorkbook();
        var worksheet = workbook.Worksheets.Add("Vulnerabilities");

        // Headers
        var headers = new[]
        {
            "Plugin ID", "Plugin Name", "Severity", "Host", "IP Address", "Port", "Protocol",
            "CVE", "Synopsis", "Solution", "Exploitable", "Status", "First Discovered",
            "Last Observed", "Site"
        };

        for (int i = 0; i < headers.Length; i++)
        {
            worksheet.Cell(1, i + 1).Value = headers[i];
            worksheet.Cell(1, i + 1).Style.Font.Bold = true;
            worksheet.Cell(1, i + 1).Style.Fill.BackgroundColor = XLColor.LightGray;
        }

        // Data
        int row = 2;
        foreach (var vuln in vulnerabilities)
        {
            worksheet.Cell(row, 1).Value = vuln.PluginId;
            worksheet.Cell(row, 2).Value = vuln.PluginName;
            worksheet.Cell(row, 3).Value = vuln.Severity.ToString();
            worksheet.Cell(row, 4).Value = vuln.Host?.DisplayName ?? vuln.Host?.DNSName ?? vuln.Host?.NetBIOSName;
            worksheet.Cell(row, 5).Value = vuln.IPAddress ?? vuln.Host?.LastKnownIPAddress;
            worksheet.Cell(row, 6).Value = vuln.Port;
            worksheet.Cell(row, 7).Value = vuln.Protocol;
            worksheet.Cell(row, 8).Value = vuln.CVE;
            worksheet.Cell(row, 9).Value = vuln.Synopsis;
            worksheet.Cell(row, 10).Value = vuln.Solution;
            worksheet.Cell(row, 11).Value = vuln.IsExploitable ? "Yes" : "No";
            worksheet.Cell(row, 12).Value = vuln.RemediationStatus.ToString();
            worksheet.Cell(row, 13).Value = vuln.FirstDiscovered?.ToString("yyyy-MM-dd");
            worksheet.Cell(row, 14).Value = vuln.LastObserved?.ToString("yyyy-MM-dd");
            worksheet.Cell(row, 15).Value = vuln.Host?.Site?.Name;

            // Color code severity
            var severityCell = worksheet.Cell(row, 3);
            severityCell.Style.Fill.BackgroundColor = vuln.Severity switch
            {
                Severity.Critical => XLColor.Red,
                Severity.High => XLColor.Orange,
                Severity.Medium => XLColor.Yellow,
                Severity.Low => XLColor.LightBlue,
                _ => XLColor.LightGray
            };

            row++;
        }

        worksheet.Columns().AdjustToContents();

        using var memoryStream = new MemoryStream();
        workbook.SaveAs(memoryStream);
        return memoryStream.ToArray();
    }

    public async Task<VulnerabilitySummaryReport> GetVulnerabilitySummaryAsync(int? siteId = null)
    {
        var report = new VulnerabilitySummaryReport();

        if (siteId.HasValue)
        {
            var site = await _context.Sites.FindAsync(siteId.Value);
            report.SiteName = site?.Name;
        }

        var query = _context.HostVulnerabilities
            .Include(v => v.Host)
            .AsQueryable();

        if (siteId.HasValue)
            query = query.Where(v => v.Host.SiteId == siteId.Value);

        var vulnerabilities = await query.ToListAsync();

        report.TotalVulnerabilities = vulnerabilities.Count;
        report.TotalHosts = vulnerabilities.Select(v => v.HostId).Distinct().Count();

        // By severity
        foreach (Severity severity in Enum.GetValues<Severity>())
        {
            report.BySeverity[severity] = vulnerabilities.Count(v => v.Severity == severity);
        }

        // By status
        foreach (RemediationStatus status in Enum.GetValues<RemediationStatus>())
        {
            report.ByStatus[status] = vulnerabilities.Count(v => v.RemediationStatus == status);
        }

        report.ExploitableCount = vulnerabilities.Count(v => v.IsExploitable);

        // Top vulnerabilities by affected host count
        report.TopVulnerabilities = vulnerabilities
            .GroupBy(v => v.PluginId)
            .Select(g => new TopVulnerability
            {
                PluginId = g.Key,
                PluginName = g.First().PluginName ?? "Unknown",
                Severity = g.First().Severity,
                AffectedHostCount = g.Select(v => v.HostId).Distinct().Count(),
                IsExploitable = g.Any(v => v.IsExploitable),
                CVE = g.First().CVE
            })
            .OrderByDescending(v => v.Severity)
            .ThenByDescending(v => v.AffectedHostCount)
            .Take(10)
            .ToList();

        // High risk hosts
        report.HighRiskHosts = vulnerabilities
            .GroupBy(v => v.Host)
            .Select(g => new HostRiskSummary
            {
                HostId = g.Key.Id,
                HostName = g.Key.DisplayName ?? g.Key.DNSName ?? g.Key.NetBIOSName ?? "Unknown",
                IPAddress = g.Key.LastKnownIPAddress,
                CriticalCount = g.Count(v => v.Severity == Severity.Critical),
                HighCount = g.Count(v => v.Severity == Severity.High),
                MediumCount = g.Count(v => v.Severity == Severity.Medium),
                TotalVulnerabilities = g.Count()
            })
            .OrderByDescending(h => h.CriticalCount)
            .ThenByDescending(h => h.HighCount)
            .Take(10)
            .ToList();

        return report;
    }

    public async Task<HostSummaryReport> GetHostSummaryAsync(int? siteId = null)
    {
        var report = new HostSummaryReport();

        if (siteId.HasValue)
        {
            var site = await _context.Sites.FindAsync(siteId.Value);
            report.SiteName = site?.Name;
        }

        var query = _context.Hosts
            .Include(h => h.Vulnerabilities)
            .AsQueryable();

        if (siteId.HasValue)
            query = query.Where(h => h.SiteId == siteId.Value);

        var hosts = await query.ToListAsync();

        report.TotalHosts = hosts.Count;
        report.ActiveHosts = hosts.Count(h => h.Status == HostStatus.Active);
        report.HostsWithVulnerabilities = hosts.Count(h => h.Vulnerabilities.Any());

        // By asset type
        foreach (AssetType type in Enum.GetValues<AssetType>())
        {
            report.ByAssetType[type] = hosts.Count(h => h.AssetType == type);
        }

        // By status
        foreach (HostStatus status in Enum.GetValues<HostStatus>())
        {
            report.ByStatus[status] = hosts.Count(h => h.Status == status);
        }

        // All hosts with vulnerability counts
        report.AllHosts = hosts
            .Select(h => new HostRiskSummary
            {
                HostId = h.Id,
                HostName = h.DisplayName ?? h.DNSName ?? h.NetBIOSName ?? "Unknown",
                IPAddress = h.LastKnownIPAddress,
                CriticalCount = h.Vulnerabilities.Count(v => v.Severity == Severity.Critical),
                HighCount = h.Vulnerabilities.Count(v => v.Severity == Severity.High),
                MediumCount = h.Vulnerabilities.Count(v => v.Severity == Severity.Medium),
                TotalVulnerabilities = h.Vulnerabilities.Count
            })
            .OrderByDescending(h => h.CriticalCount)
            .ThenByDescending(h => h.HighCount)
            .ToList();

        return report;
    }

    private async Task<List<HostVulnerability>> GetFilteredVulnerabilitiesAsync(VulnerabilityExportCriteria criteria)
    {
        var query = _context.HostVulnerabilities
            .Include(v => v.Host)
            .ThenInclude(h => h.Site)
            .AsQueryable();

        if (criteria.SiteId.HasValue)
            query = query.Where(v => v.Host.SiteId == criteria.SiteId.Value);

        if (criteria.HostId.HasValue)
            query = query.Where(v => v.HostId == criteria.HostId.Value);

        if (criteria.MinimumSeverity.HasValue)
            query = query.Where(v => v.Severity >= criteria.MinimumSeverity.Value);

        if (criteria.Status.HasValue)
            query = query.Where(v => v.RemediationStatus == criteria.Status.Value);

        if (criteria.IsExploitable.HasValue)
            query = query.Where(v => v.IsExploitable == criteria.IsExploitable.Value);

        if (!criteria.IncludeRemediated)
            query = query.Where(v => v.RemediationStatus != RemediationStatus.Remediated &&
                                     v.RemediationStatus != RemediationStatus.FalsePositive);

        return await query
            .OrderByDescending(v => v.Severity)
            .ThenBy(v => v.Host.DisplayName)
            .ToListAsync();
    }
}
