using System.ComponentModel.DataAnnotations;
using VulnMgmt.Web.Models.Domain;

namespace VulnMgmt.Web.Models.ViewModels;

/// <summary>
/// View model for scan import file upload
/// </summary>
public class ScanUploadViewModel
{
    [Required(ErrorMessage = "Please select a site")]
    [Display(Name = "Target Site")]
    public int SiteId { get; set; }

    [Required(ErrorMessage = "Please select a file to upload")]
    [Display(Name = "Scan File (CSV)")]
    public IFormFile? File { get; set; }

    [Display(Name = "Update existing vulnerabilities")]
    public bool UpdateExisting { get; set; } = true;

    [Display(Name = "Notes")]
    [StringLength(1000)]
    public string? Notes { get; set; }

    public IEnumerable<Site> AvailableSites { get; set; } = new List<Site>();
}

/// <summary>
/// Result of a scan import operation
/// </summary>
public class ScanImportResultViewModel
{
    public bool Success { get; set; }
    public string Message { get; set; } = string.Empty;
    public int ScanImportId { get; set; }
    public string FileName { get; set; } = string.Empty;
    public string SiteName { get; set; } = string.Empty;
    public int TotalRows { get; set; }
    public int HostsCreated { get; set; }
    public int HostsUpdated { get; set; }
    public int VulnerabilitiesImported { get; set; }
    public int VulnerabilitiesUpdated { get; set; }
    public int VulnerabilitiesSkipped { get; set; }
    public List<string> Errors { get; set; } = new();
    public List<string> Warnings { get; set; } = new();
    public TimeSpan ProcessingTime { get; set; }
}

/// <summary>
/// View model for scan import history list
/// </summary>
public class ScanImportListViewModel
{
    public IEnumerable<ScanImportListItem> Imports { get; set; } = new List<ScanImportListItem>();
    public int? FilterSiteId { get; set; }
    public IEnumerable<Site> AvailableSites { get; set; } = new List<Site>();
}

public class ScanImportListItem
{
    public int Id { get; set; }
    public string FileName { get; set; } = string.Empty;
    public string SiteName { get; set; } = string.Empty;
    public int SiteId { get; set; }
    public DateTime ImportDate { get; set; }
    public string? ImportedBy { get; set; }
    public int TotalRows { get; set; }
    public int HostsCreated { get; set; }
    public int HostsUpdated { get; set; }
    public int VulnerabilitiesImported { get; set; }
    public int VulnerabilitiesUpdated { get; set; }
    public string? Notes { get; set; }
}

/// <summary>
/// Nessus CSV row mapping
/// </summary>
public class NessusCsvRow
{
    public int PluginID { get; set; }
    public string? CVE { get; set; }
    public string? CVSS { get; set; }
    public string? Risk { get; set; }
    public string? Host { get; set; }
    public string? Protocol { get; set; }
    public int? Port { get; set; }
    public string? Name { get; set; }
    public string? Synopsis { get; set; }
    public string? Description { get; set; }
    public string? Solution { get; set; }
    public string? SeeAlso { get; set; }
    public string? PluginOutput { get; set; }

    // Additional common Nessus columns
    public string? MACAddress { get; set; }
    public string? DNSName { get; set; }
    public string? NetBIOSName { get; set; }
    public string? PluginFamily { get; set; }
    public string? ExploitAvailable { get; set; }
    public string? ExploitEase { get; set; }
    public string? ExploitFrameworks { get; set; }
    public string? PluginPublicationDate { get; set; }
    public string? VulnPublicationDate { get; set; }
}
