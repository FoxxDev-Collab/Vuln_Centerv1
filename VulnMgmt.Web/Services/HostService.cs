using Microsoft.EntityFrameworkCore;
using VulnMgmt.Web.Data;
using VulnMgmt.Web.Models.Domain;
using DomainHost = VulnMgmt.Web.Models.Domain.Host;

namespace VulnMgmt.Web.Services;

public class HostService : IHostService
{
    private readonly ApplicationDbContext _context;

    public HostService(ApplicationDbContext context)
    {
        _context = context;
    }

    public async Task<IEnumerable<DomainHost>> GetAllAsync()
    {
        return await _context.Hosts
            .Include(h => h.Site)
            .OrderBy(h => h.Site.Name)
            .ThenBy(h => h.DisplayName ?? h.DNSName ?? h.NetBIOSName)
            .ToListAsync();
    }

    public async Task<IEnumerable<DomainHost>> GetBySiteAsync(int siteId)
    {
        return await _context.Hosts
            .Where(h => h.SiteId == siteId)
            .OrderBy(h => h.DisplayName ?? h.DNSName ?? h.NetBIOSName)
            .ToListAsync();
    }

    public async Task<DomainHost?> GetByIdAsync(int id)
    {
        return await _context.Hosts
            .Include(h => h.Site)
            .FirstOrDefaultAsync(h => h.Id == id);
    }

    public async Task<DomainHost?> GetByIdWithVulnerabilitiesAsync(int id)
    {
        return await _context.Hosts
            .Include(h => h.Site)
            .Include(h => h.Vulnerabilities)
            .FirstOrDefaultAsync(h => h.Id == id);
    }

    public async Task<DomainHost> CreateAsync(DomainHost host)
    {
        host.CreatedDate = DateTime.UtcNow;
        host.ModifiedDate = DateTime.UtcNow;

        _context.Hosts.Add(host);
        await _context.SaveChangesAsync();

        return host;
    }

    public async Task<DomainHost> UpdateAsync(DomainHost host)
    {
        host.ModifiedDate = DateTime.UtcNow;

        _context.Hosts.Update(host);
        await _context.SaveChangesAsync();

        return host;
    }

    public async Task DeleteAsync(int id)
    {
        var host = await _context.Hosts.FindAsync(id);
        if (host != null)
        {
            _context.Hosts.Remove(host);
            await _context.SaveChangesAsync();
        }
    }

    public async Task<bool> ExistsAsync(int id)
    {
        return await _context.Hosts.AnyAsync(h => h.Id == id);
    }

    public async Task<DomainHost?> FindByDnsOrNetBiosAsync(int siteId, string? dnsName, string? netBiosName)
    {
        if (string.IsNullOrEmpty(dnsName) && string.IsNullOrEmpty(netBiosName))
            return null;

        var query = _context.Hosts.Where(h => h.SiteId == siteId);

        if (!string.IsNullOrEmpty(dnsName))
        {
            var hostByDns = await query.FirstOrDefaultAsync(h =>
                h.DNSName != null && h.DNSName.ToLower() == dnsName.ToLower());
            if (hostByDns != null)
                return hostByDns;
        }

        if (!string.IsNullOrEmpty(netBiosName))
        {
            var hostByNetBios = await query.FirstOrDefaultAsync(h =>
                h.NetBIOSName != null && h.NetBIOSName.ToLower() == netBiosName.ToLower());
            if (hostByNetBios != null)
                return hostByNetBios;
        }

        return null;
    }

    public async Task<HostVulnSummary> GetHostVulnSummaryAsync(int hostId)
    {
        var vulns = await _context.HostVulnerabilities
            .Where(v => v.HostId == hostId)
            .ToListAsync();

        var openStatuses = new[] { RemediationStatus.Open, RemediationStatus.InProgress };

        return new HostVulnSummary
        {
            TotalVulnerabilities = vulns.Count,
            OpenCount = vulns.Count(v => openStatuses.Contains(v.RemediationStatus)),
            CriticalCount = vulns.Count(v => v.Severity == Severity.Critical && openStatuses.Contains(v.RemediationStatus)),
            HighCount = vulns.Count(v => v.Severity == Severity.High && openStatuses.Contains(v.RemediationStatus)),
            MediumCount = vulns.Count(v => v.Severity == Severity.Medium && openStatuses.Contains(v.RemediationStatus)),
            LowCount = vulns.Count(v => v.Severity == Severity.Low && openStatuses.Contains(v.RemediationStatus)),
            InfoCount = vulns.Count(v => v.Severity == Severity.Info && openStatuses.Contains(v.RemediationStatus)),
            RemediatedCount = vulns.Count(v => v.RemediationStatus == RemediationStatus.Remediated),
            AcceptedCount = vulns.Count(v => v.RemediationStatus == RemediationStatus.Accepted || v.RemediationStatus == RemediationStatus.FalsePositive)
        };
    }
}
