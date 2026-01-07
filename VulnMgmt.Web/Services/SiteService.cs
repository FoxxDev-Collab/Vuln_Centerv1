using Microsoft.EntityFrameworkCore;
using VulnMgmt.Web.Data;
using VulnMgmt.Web.Models.Domain;

namespace VulnMgmt.Web.Services;

public class SiteService : ISiteService
{
    private readonly ApplicationDbContext _context;

    public SiteService(ApplicationDbContext context)
    {
        _context = context;
    }

    public async Task<IEnumerable<Site>> GetAllAsync()
    {
        return await _context.Sites
            .OrderBy(s => s.Name)
            .ToListAsync();
    }

    public async Task<Site?> GetByIdAsync(int id)
    {
        return await _context.Sites.FindAsync(id);
    }

    public async Task<Site?> GetByIdWithHostsAsync(int id)
    {
        return await _context.Sites
            .Include(s => s.Hosts)
            .FirstOrDefaultAsync(s => s.Id == id);
    }

    public async Task<Site> CreateAsync(Site site)
    {
        site.CreatedDate = DateTime.UtcNow;
        site.ModifiedDate = DateTime.UtcNow;

        _context.Sites.Add(site);
        await _context.SaveChangesAsync();

        return site;
    }

    public async Task<Site> UpdateAsync(Site site)
    {
        site.ModifiedDate = DateTime.UtcNow;

        _context.Sites.Update(site);
        await _context.SaveChangesAsync();

        return site;
    }

    public async Task DeleteAsync(int id)
    {
        var site = await _context.Sites.FindAsync(id);
        if (site != null)
        {
            _context.Sites.Remove(site);
            await _context.SaveChangesAsync();
        }
    }

    public async Task<bool> ExistsAsync(int id)
    {
        return await _context.Sites.AnyAsync(s => s.Id == id);
    }

    public async Task<SiteSummary> GetSiteSummaryAsync(int id)
    {
        var hosts = await _context.Hosts
            .Where(h => h.SiteId == id)
            .ToListAsync();

        var hostIds = hosts.Select(h => h.Id).ToList();

        var openStatuses = new[] { RemediationStatus.Open, RemediationStatus.InProgress };

        var vulns = await _context.HostVulnerabilities
            .Where(v => hostIds.Contains(v.HostId) && openStatuses.Contains(v.RemediationStatus))
            .ToListAsync();

        return new SiteSummary
        {
            TotalHosts = hosts.Count,
            ActiveHosts = hosts.Count(h => h.Status == HostStatus.Active),
            TotalVulnerabilities = vulns.Count,
            CriticalCount = vulns.Count(v => v.Severity == Severity.Critical),
            HighCount = vulns.Count(v => v.Severity == Severity.High),
            MediumCount = vulns.Count(v => v.Severity == Severity.Medium),
            LowCount = vulns.Count(v => v.Severity == Severity.Low),
            InfoCount = vulns.Count(v => v.Severity == Severity.Info),
            LastScanDate = hosts.Max(h => h.LastScanDate)
        };
    }
}
