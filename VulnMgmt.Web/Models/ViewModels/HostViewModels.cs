using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc.Rendering;
using VulnMgmt.Web.Models.Domain;
using VulnMgmt.Web.Services;
using DomainHost = VulnMgmt.Web.Models.Domain.Host;

namespace VulnMgmt.Web.Models.ViewModels;

public class HostIndexViewModel
{
    public IEnumerable<HostIndexItem> Hosts { get; set; } = new List<HostIndexItem>();
    public int? SiteId { get; set; }
    public string? SiteName { get; set; }
    public string? SearchTerm { get; set; }
    public HostStatus? StatusFilter { get; set; }
}

public class HostIndexItem
{
    public int Id { get; set; }
    public string DisplayName { get; set; } = string.Empty;
    public string? DNSName { get; set; }
    public string? LastKnownIPAddress { get; set; }
    public string? OperatingSystem { get; set; }
    public string SiteName { get; set; } = string.Empty;
    public int SiteId { get; set; }
    public HostStatus Status { get; set; }
    public AssetType AssetType { get; set; }
    public int OpenVulnCount { get; set; }
    public int CriticalCount { get; set; }
    public int HighCount { get; set; }
    public DateTime? LastScanDate { get; set; }
    // STIG data
    public int StigChecklistCount { get; set; }
    public int StigOpenCount { get; set; }
}

public class HostDetailsViewModel
{
    public DomainHost Host { get; set; } = null!;
    public HostVulnSummary Summary { get; set; } = null!;
    public IEnumerable<VulnerabilityListItem> Vulnerabilities { get; set; } = new List<VulnerabilityListItem>();
}

public class HostCreateViewModel
{
    public int SiteId { get; set; }

    [Display(Name = "Site")]
    public string? SiteName { get; set; }

    [StringLength(255)]
    [Display(Name = "DNS Name")]
    public string? DNSName { get; set; }

    [StringLength(15)]
    [Display(Name = "NetBIOS Name")]
    public string? NetBIOSName { get; set; }

    [StringLength(100)]
    [Display(Name = "Display Name")]
    public string? DisplayName { get; set; }

    [StringLength(500)]
    public string? Description { get; set; }

    [StringLength(200)]
    [Display(Name = "Operating System")]
    public string? OperatingSystem { get; set; }

    [StringLength(100)]
    [Display(Name = "OS Version")]
    public string? OSVersion { get; set; }

    [StringLength(45)]
    [Display(Name = "IP Address")]
    public string? LastKnownIPAddress { get; set; }

    [StringLength(17)]
    [Display(Name = "MAC Address")]
    public string? LastKnownMACAddress { get; set; }

    [Display(Name = "Asset Type")]
    public AssetType AssetType { get; set; } = AssetType.Unknown;

    [StringLength(50)]
    [Display(Name = "Asset Tag")]
    public string? AssetTag { get; set; }

    [StringLength(50)]
    [Display(Name = "Serial Number")]
    public string? SerialNumber { get; set; }

    public HostStatus Status { get; set; } = HostStatus.Active;

    public SelectList? Sites { get; set; }
}

public class HostEditViewModel : HostCreateViewModel
{
    public int Id { get; set; }
    public DateTime CreatedDate { get; set; }
    public DateTime? LastScanDate { get; set; }
    public int LastScanVulnCount { get; set; }
}

public class VulnerabilityListItem
{
    public int Id { get; set; }
    public int PluginId { get; set; }
    public string? PluginName { get; set; }
    public string? Family { get; set; }
    public Severity Severity { get; set; }
    public string? CVE { get; set; }
    public int? Port { get; set; }
    public string? Protocol { get; set; }
    public RemediationStatus RemediationStatus { get; set; }
    public DateTime? LastObserved { get; set; }
    public DateTime? FirstDiscovered { get; set; }
    public bool IsExploitable { get; set; }
}
