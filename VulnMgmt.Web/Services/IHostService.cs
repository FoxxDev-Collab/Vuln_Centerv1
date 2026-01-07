using VulnMgmt.Web.Models.Domain;
using DomainHost = VulnMgmt.Web.Models.Domain.Host;

namespace VulnMgmt.Web.Services;

public interface IHostService
{
    Task<IEnumerable<DomainHost>> GetAllAsync();
    Task<IEnumerable<DomainHost>> GetBySiteAsync(int siteId);
    Task<DomainHost?> GetByIdAsync(int id);
    Task<DomainHost?> GetByIdWithVulnerabilitiesAsync(int id);
    Task<DomainHost> CreateAsync(DomainHost host);
    Task<DomainHost> UpdateAsync(DomainHost host);
    Task DeleteAsync(int id);
    Task<bool> ExistsAsync(int id);
    Task<DomainHost?> FindByDnsOrNetBiosAsync(int siteId, string? dnsName, string? netBiosName);
    Task<HostVulnSummary> GetHostVulnSummaryAsync(int hostId);
}

public class HostVulnSummary
{
    public int TotalVulnerabilities { get; set; }
    public int OpenCount { get; set; }
    public int CriticalCount { get; set; }
    public int HighCount { get; set; }
    public int MediumCount { get; set; }
    public int LowCount { get; set; }
    public int InfoCount { get; set; }
    public int RemediatedCount { get; set; }
    public int AcceptedCount { get; set; }
}
