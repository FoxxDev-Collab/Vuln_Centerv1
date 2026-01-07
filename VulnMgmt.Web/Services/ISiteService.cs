using VulnMgmt.Web.Models.Domain;

namespace VulnMgmt.Web.Services;

public interface ISiteService
{
    Task<IEnumerable<Site>> GetAllAsync();
    Task<Site?> GetByIdAsync(int id);
    Task<Site?> GetByIdWithHostsAsync(int id);
    Task<Site> CreateAsync(Site site);
    Task<Site> UpdateAsync(Site site);
    Task DeleteAsync(int id);
    Task<bool> ExistsAsync(int id);
    Task<SiteSummary> GetSiteSummaryAsync(int id);
}

public class SiteSummary
{
    public int TotalHosts { get; set; }
    public int ActiveHosts { get; set; }
    public int TotalVulnerabilities { get; set; }
    public int CriticalCount { get; set; }
    public int HighCount { get; set; }
    public int MediumCount { get; set; }
    public int LowCount { get; set; }
    public int InfoCount { get; set; }
    public DateTime? LastScanDate { get; set; }
}
