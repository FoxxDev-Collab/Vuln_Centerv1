using System.ComponentModel.DataAnnotations;
using VulnMgmt.Web.Models.Domain;
using VulnMgmt.Web.Services;

namespace VulnMgmt.Web.Models.ViewModels;

public class SiteListViewModel
{
    public IEnumerable<SiteListItem> Sites { get; set; } = new List<SiteListItem>();
}

public class SiteListItem
{
    public int Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string? OrganizationName { get; set; }
    public string? Location { get; set; }
    public bool IsActive { get; set; }
    public int HostCount { get; set; }
    public int VulnCount { get; set; }
    public int CriticalHighCount { get; set; }
    public DateTime? LastScanDate { get; set; }
    // STIG data
    public int StigChecklistCount { get; set; }
    public int StigOpenCount { get; set; }
}

public class SiteDetailsViewModel
{
    public Site Site { get; set; } = null!;
    public SiteSummary Summary { get; set; } = null!;
    public IEnumerable<HostListItem> Hosts { get; set; } = new List<HostListItem>();
}

public class SiteCreateViewModel
{
    [Required]
    [StringLength(100)]
    [Display(Name = "Site Name")]
    public string Name { get; set; } = string.Empty;

    [StringLength(500)]
    public string? Description { get; set; }

    [StringLength(200)]
    public string? Location { get; set; }

    [StringLength(200)]
    [Display(Name = "Organization")]
    public string? OrganizationName { get; set; }

    [StringLength(100)]
    [Display(Name = "POC Name")]
    public string? POCName { get; set; }

    [StringLength(100)]
    [EmailAddress]
    [Display(Name = "POC Email")]
    public string? POCEmail { get; set; }

    [StringLength(20)]
    [Phone]
    [Display(Name = "POC Phone")]
    public string? POCPhone { get; set; }

    [Display(Name = "Active")]
    public bool IsActive { get; set; } = true;
}

public class SiteEditViewModel : SiteCreateViewModel
{
    public int Id { get; set; }
    public DateTime CreatedDate { get; set; }
}

public class HostListItem
{
    public int Id { get; set; }
    public string DisplayName { get; set; } = string.Empty;
    public string? DNSName { get; set; }
    public string? LastKnownIPAddress { get; set; }
    public string? OperatingSystem { get; set; }
    public HostStatus Status { get; set; }
    public int VulnCount { get; set; }
    public int CriticalCount { get; set; }
    public int HighCount { get; set; }
    public DateTime? LastScanDate { get; set; }
}
