using System.ComponentModel.DataAnnotations;
using VulnMgmt.Web.Models.Domain;

namespace VulnMgmt.Web.Models.ViewModels;

public class ReportsDashboardViewModel
{
    public IEnumerable<Site> AvailableSites { get; set; } = new List<Site>();
}

public class ExportViewModel
{
    [Display(Name = "Site")]
    public int? SiteId { get; set; }

    [Display(Name = "Minimum Severity")]
    public Severity? MinimumSeverity { get; set; }

    [Display(Name = "Remediation Status")]
    public RemediationStatus? Status { get; set; }

    [Display(Name = "Exploitable Only")]
    public bool ExploitableOnly { get; set; }

    [Display(Name = "Include Remediated")]
    public bool IncludeRemediated { get; set; }

    public IEnumerable<Site> AvailableSites { get; set; } = new List<Site>();
}
