using System.Diagnostics;
using System.Globalization;
using CsvHelper;
using CsvHelper.Configuration;
using Microsoft.EntityFrameworkCore;
using VulnMgmt.Web.Data;
using VulnMgmt.Web.Models.Domain;
using VulnMgmt.Web.Models.ViewModels;
using DomainHost = VulnMgmt.Web.Models.Domain.Host;

namespace VulnMgmt.Web.Services;

public class ScanImportService : IScanImportService
{
    private readonly ApplicationDbContext _context;
    private readonly ILogger<ScanImportService> _logger;

    public ScanImportService(ApplicationDbContext context, ILogger<ScanImportService> logger)
    {
        _context = context;
        _logger = logger;
    }

    public async Task<ScanImportResultViewModel> ImportNessusCsvAsync(
        Stream fileStream,
        string fileName,
        int siteId,
        int? importedById,
        bool updateExisting = true,
        string? notes = null)
    {
        var stopwatch = Stopwatch.StartNew();
        var result = new ScanImportResultViewModel
        {
            FileName = fileName,
            Success = false
        };

        try
        {
            var site = await _context.Sites.FindAsync(siteId);
            if (site == null)
            {
                result.Errors.Add($"Site with ID {siteId} not found.");
                return result;
            }
            result.SiteName = site.Name;

            // Parse CSV
            var rows = await ParseCsvAsync(fileStream, result);
            if (rows == null || !rows.Any())
            {
                if (!result.Errors.Any())
                    result.Errors.Add("No valid rows found in the CSV file.");
                return result;
            }

            result.TotalRows = rows.Count;
            _logger.LogInformation("Parsed {RowCount} rows from {FileName}", rows.Count, fileName);

            // Process rows
            var hostCache = new Dictionary<string, DomainHost>(StringComparer.OrdinalIgnoreCase);
            var existingHosts = await _context.Hosts
                .Where(h => h.SiteId == siteId)
                .ToListAsync();

            foreach (var host in existingHosts)
            {
                var key = GetHostKey(host.DNSName, host.NetBIOSName, host.LastKnownIPAddress);
                if (!string.IsNullOrEmpty(key) && !hostCache.ContainsKey(key))
                    hostCache[key] = host;
            }

            foreach (var row in rows)
            {
                try
                {
                    await ProcessRowAsync(row, siteId, hostCache, updateExisting, fileName, result);
                }
                catch (Exception ex)
                {
                    result.Warnings.Add($"Error processing row (Plugin {row.PluginID}): {ex.Message}");
                    _logger.LogWarning(ex, "Error processing row for Plugin {PluginId}", row.PluginID);
                }
            }

            // Save changes
            await _context.SaveChangesAsync();

            // Create import record
            var scanImport = new ScanImport
            {
                SiteId = siteId,
                FileName = fileName,
                ImportDate = DateTime.UtcNow,
                TotalRows = result.TotalRows,
                HostsCreated = result.HostsCreated,
                HostsUpdated = result.HostsUpdated,
                VulnerabilitiesImported = result.VulnerabilitiesImported,
                VulnerabilitiesUpdated = result.VulnerabilitiesUpdated,
                ImportedById = importedById,
                Notes = notes
            };

            _context.ScanImports.Add(scanImport);
            await _context.SaveChangesAsync();

            result.ScanImportId = scanImport.Id;
            result.Success = true;
            result.Message = $"Successfully imported {result.VulnerabilitiesImported} new vulnerabilities and updated {result.VulnerabilitiesUpdated} existing.";

            _logger.LogInformation(
                "Import completed: {VulnsImported} new, {VulnsUpdated} updated, {HostsCreated} hosts created, {HostsUpdated} hosts updated",
                result.VulnerabilitiesImported, result.VulnerabilitiesUpdated, result.HostsCreated, result.HostsUpdated);
        }
        catch (Exception ex)
        {
            result.Errors.Add($"Import failed: {ex.Message}");
            _logger.LogError(ex, "Import failed for {FileName}", fileName);
        }

        stopwatch.Stop();
        result.ProcessingTime = stopwatch.Elapsed;
        return result;
    }

    private async Task<List<NessusCsvRow>?> ParseCsvAsync(Stream fileStream, ScanImportResultViewModel result)
    {
        var rows = new List<NessusCsvRow>();

        try
        {
            using var reader = new StreamReader(fileStream);
            var config = new CsvConfiguration(CultureInfo.InvariantCulture)
            {
                HeaderValidated = null,
                MissingFieldFound = null,
                BadDataFound = context =>
                {
                    result.Warnings.Add($"Bad data at row {context.Context.Parser?.Row}: {context.Field}");
                }
            };

            using var csv = new CsvReader(reader, config);

            // Register class map for flexible column mapping
            csv.Context.RegisterClassMap<NessusCsvRowMap>();

            await foreach (var row in csv.GetRecordsAsync<NessusCsvRow>())
            {
                if (row.PluginID > 0) // Valid row must have plugin ID
                    rows.Add(row);
            }
        }
        catch (Exception ex)
        {
            result.Errors.Add($"Error parsing CSV: {ex.Message}");
            _logger.LogError(ex, "Error parsing CSV file");
            return null;
        }

        return rows;
    }

    private async Task ProcessRowAsync(
        NessusCsvRow row,
        int siteId,
        Dictionary<string, DomainHost> hostCache,
        bool updateExisting,
        string importSource,
        ScanImportResultViewModel result)
    {
        // Find or create host
        var hostKey = GetHostKey(row.DNSName, row.NetBIOSName, row.Host);
        if (string.IsNullOrEmpty(hostKey))
        {
            result.Warnings.Add($"Row skipped - no host identifier for Plugin {row.PluginID}");
            result.VulnerabilitiesSkipped++;
            return;
        }

        DomainHost host;
        if (hostCache.TryGetValue(hostKey, out var existingHost))
        {
            host = existingHost;
            // Update host info if we have more data
            var updated = UpdateHostFromRow(host, row);
            if (updated)
                result.HostsUpdated++;
        }
        else
        {
            host = CreateHostFromRow(row, siteId);
            _context.Hosts.Add(host);
            await _context.SaveChangesAsync(); // Save to get ID
            hostCache[hostKey] = host;
            result.HostsCreated++;
        }

        // Check for existing vulnerability
        var existingVuln = await _context.HostVulnerabilities
            .FirstOrDefaultAsync(v => v.HostId == host.Id && v.PluginId == row.PluginID);

        if (existingVuln != null)
        {
            if (updateExisting)
            {
                UpdateVulnerabilityFromRow(existingVuln, row, importSource);
                result.VulnerabilitiesUpdated++;
            }
            else
            {
                result.VulnerabilitiesSkipped++;
            }
        }
        else
        {
            var vuln = CreateVulnerabilityFromRow(row, host.Id, importSource);
            _context.HostVulnerabilities.Add(vuln);
            result.VulnerabilitiesImported++;
        }

        // Update host last scan info
        host.LastScanDate = DateTime.UtcNow;
        host.ModifiedDate = DateTime.UtcNow;
    }

    private string? GetHostKey(string? dnsName, string? netbiosName, string? ipAddress)
    {
        if (!string.IsNullOrWhiteSpace(dnsName))
            return dnsName.Trim().ToLowerInvariant();
        if (!string.IsNullOrWhiteSpace(netbiosName))
            return netbiosName.Trim().ToLowerInvariant();
        if (!string.IsNullOrWhiteSpace(ipAddress))
            return ipAddress.Trim();
        return null;
    }

    private DomainHost CreateHostFromRow(NessusCsvRow row, int siteId)
    {
        return new DomainHost
        {
            SiteId = siteId,
            DNSName = row.DNSName?.Trim(),
            NetBIOSName = row.NetBIOSName?.Trim(),
            DisplayName = row.DNSName ?? row.NetBIOSName ?? row.Host,
            LastKnownIPAddress = row.Host?.Trim(),
            LastKnownMACAddress = row.MACAddress?.Trim(),
            Status = HostStatus.Active,
            LastScanDate = DateTime.UtcNow,
            CreatedDate = DateTime.UtcNow,
            ModifiedDate = DateTime.UtcNow
        };
    }

    private bool UpdateHostFromRow(DomainHost host, NessusCsvRow row)
    {
        var updated = false;

        if (string.IsNullOrEmpty(host.DNSName) && !string.IsNullOrEmpty(row.DNSName))
        {
            host.DNSName = row.DNSName.Trim();
            updated = true;
        }
        if (string.IsNullOrEmpty(host.NetBIOSName) && !string.IsNullOrEmpty(row.NetBIOSName))
        {
            host.NetBIOSName = row.NetBIOSName.Trim();
            updated = true;
        }
        if (!string.IsNullOrEmpty(row.Host))
        {
            host.LastKnownIPAddress = row.Host.Trim();
            updated = true;
        }
        if (!string.IsNullOrEmpty(row.MACAddress))
        {
            host.LastKnownMACAddress = row.MACAddress.Trim();
            updated = true;
        }

        if (updated)
            host.ModifiedDate = DateTime.UtcNow;

        return updated;
    }

    private HostVulnerability CreateVulnerabilityFromRow(NessusCsvRow row, int hostId, string importSource)
    {
        return new HostVulnerability
        {
            HostId = hostId,
            PluginId = row.PluginID,
            PluginName = row.Name?.Trim(),
            Family = row.PluginFamily?.Trim(),
            Severity = ParseSeverity(row.Risk),
            IPAddress = row.Host?.Trim(),
            Protocol = row.Protocol?.Trim(),
            Port = row.Port,
            MACAddress = row.MACAddress?.Trim(),
            IsExploitable = ParseBool(row.ExploitAvailable),
            ExploitFrameworks = row.ExploitFrameworks?.Trim(),
            ExploitEase = row.ExploitEase?.Trim(),
            CVE = row.CVE?.Trim(),
            VulnPublicationDate = ParseDate(row.VulnPublicationDate),
            Synopsis = row.Synopsis?.Trim(),
            Description = row.Description,
            Solution = row.Solution,
            SeeAlso = row.SeeAlso,
            PluginText = row.PluginOutput,
            FirstDiscovered = DateTime.UtcNow,
            LastObserved = DateTime.UtcNow,
            RemediationStatus = RemediationStatus.Open,
            ImportedDate = DateTime.UtcNow,
            ImportSource = importSource,
            CreatedDate = DateTime.UtcNow,
            ModifiedDate = DateTime.UtcNow
        };
    }

    private void UpdateVulnerabilityFromRow(HostVulnerability vuln, NessusCsvRow row, string importSource)
    {
        vuln.LastObserved = DateTime.UtcNow;
        vuln.PluginName = row.Name?.Trim() ?? vuln.PluginName;
        vuln.Family = row.PluginFamily?.Trim() ?? vuln.Family;
        vuln.Severity = ParseSeverity(row.Risk);
        vuln.IPAddress = row.Host?.Trim() ?? vuln.IPAddress;
        vuln.Protocol = row.Protocol?.Trim() ?? vuln.Protocol;
        vuln.Port = row.Port ?? vuln.Port;
        vuln.IsExploitable = ParseBool(row.ExploitAvailable);
        vuln.ExploitFrameworks = row.ExploitFrameworks?.Trim() ?? vuln.ExploitFrameworks;
        vuln.ExploitEase = row.ExploitEase?.Trim() ?? vuln.ExploitEase;
        vuln.CVE = row.CVE?.Trim() ?? vuln.CVE;
        vuln.Synopsis = row.Synopsis?.Trim() ?? vuln.Synopsis;
        vuln.Description = row.Description ?? vuln.Description;
        vuln.Solution = row.Solution ?? vuln.Solution;
        vuln.SeeAlso = row.SeeAlso ?? vuln.SeeAlso;
        vuln.PluginText = row.PluginOutput ?? vuln.PluginText;
        vuln.ImportSource = importSource;
        vuln.ModifiedDate = DateTime.UtcNow;

        // Reopen if previously remediated and found again
        if (vuln.RemediationStatus == RemediationStatus.Remediated ||
            vuln.RemediationStatus == RemediationStatus.FalsePositive)
        {
            vuln.RemediationStatus = RemediationStatus.Open;
            vuln.RemediationNotes = $"[{DateTime.UtcNow:yyyy-MM-dd}] Re-opened - found in scan import";
        }
    }

    private static Severity ParseSeverity(string? risk)
    {
        return risk?.ToLowerInvariant() switch
        {
            "critical" => Severity.Critical,
            "high" => Severity.High,
            "medium" => Severity.Medium,
            "low" => Severity.Low,
            "none" or "info" or "informational" => Severity.Info,
            _ => Severity.Info
        };
    }

    private static bool ParseBool(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return false;
        return value.Equals("true", StringComparison.OrdinalIgnoreCase) ||
               value.Equals("yes", StringComparison.OrdinalIgnoreCase) ||
               value.Equals("1", StringComparison.Ordinal);
    }

    private static DateTime? ParseDate(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        if (DateTime.TryParse(value, out var date))
            return date;
        return null;
    }

    public async Task<IEnumerable<ScanImportListItem>> GetAllImportsAsync(int? siteId = null)
    {
        var query = _context.ScanImports
            .Include(s => s.Site)
            .Include(s => s.ImportedBy)
            .AsQueryable();

        if (siteId.HasValue)
            query = query.Where(s => s.SiteId == siteId.Value);

        return await query
            .OrderByDescending(s => s.ImportDate)
            .Select(s => new ScanImportListItem
            {
                Id = s.Id,
                FileName = s.FileName,
                SiteName = s.Site.Name,
                SiteId = s.SiteId,
                ImportDate = s.ImportDate,
                ImportedBy = s.ImportedBy != null ? s.ImportedBy.DisplayName ?? s.ImportedBy.Username : null,
                TotalRows = s.TotalRows,
                HostsCreated = s.HostsCreated,
                HostsUpdated = s.HostsUpdated,
                VulnerabilitiesImported = s.VulnerabilitiesImported,
                VulnerabilitiesUpdated = s.VulnerabilitiesUpdated,
                Notes = s.Notes
            })
            .ToListAsync();
    }

    public async Task<ScanImport?> GetImportByIdAsync(int id)
    {
        return await _context.ScanImports
            .Include(s => s.Site)
            .Include(s => s.ImportedBy)
            .FirstOrDefaultAsync(s => s.Id == id);
    }

    public async Task DeleteImportAsync(int id)
    {
        var import = await _context.ScanImports.FindAsync(id);
        if (import != null)
        {
            _context.ScanImports.Remove(import);
            await _context.SaveChangesAsync();
        }
    }
}

/// <summary>
/// CSV mapping for Nessus export files
/// </summary>
public sealed class NessusCsvRowMap : ClassMap<NessusCsvRow>
{
    public NessusCsvRowMap()
    {
        Map(m => m.PluginID).Name("Plugin ID", "PluginID", "Plugin");
        Map(m => m.CVE).Name("CVE", "CVEs");
        Map(m => m.CVSS).Name("CVSS", "CVSS v2.0 Base Score", "CVSS v3.0 Base Score");
        Map(m => m.Risk).Name("Risk", "Severity", "Risk Factor");
        Map(m => m.Host).Name("Host", "IP Address", "IP");
        Map(m => m.Protocol).Name("Protocol");
        Map(m => m.Port).Name("Port");
        Map(m => m.Name).Name("Name", "Plugin Name");
        Map(m => m.Synopsis).Name("Synopsis");
        Map(m => m.Description).Name("Description");
        Map(m => m.Solution).Name("Solution");
        Map(m => m.SeeAlso).Name("See Also", "SeeAlso");
        Map(m => m.PluginOutput).Name("Plugin Output", "PluginOutput", "Output");
        Map(m => m.MACAddress).Name("MAC Address", "MACAddress", "MAC");
        Map(m => m.DNSName).Name("DNS Name", "DNSName", "FQDN", "DNS");
        Map(m => m.NetBIOSName).Name("NetBIOS Name", "NetBIOSName", "NetBIOS");
        Map(m => m.PluginFamily).Name("Plugin Family", "Family");
        Map(m => m.ExploitAvailable).Name("Exploit?", "Exploit Available", "ExploitAvailable");
        Map(m => m.ExploitEase).Name("Exploit Ease", "ExploitEase");
        Map(m => m.ExploitFrameworks).Name("Exploit Frameworks", "ExploitFrameworks");
        Map(m => m.PluginPublicationDate).Name("Plugin Publication Date");
        Map(m => m.VulnPublicationDate).Name("Vuln Publication Date", "Vulnerability Publication Date");
    }
}
