using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using VulnMgmt.Web.Models.Domain;
using VulnMgmt.Web.Models.ViewModels;
using VulnMgmt.Web.Services;

namespace VulnMgmt.Web.Controllers;

[Authorize(Policy = "CanView")]
public class ReportsController : Controller
{
    private readonly IReportService _reportService;
    private readonly ISiteService _siteService;
    private readonly ILogger<ReportsController> _logger;

    public ReportsController(
        IReportService reportService,
        ISiteService siteService,
        ILogger<ReportsController> logger)
    {
        _reportService = reportService;
        _siteService = siteService;
        _logger = logger;
    }

    // GET: Reports
    public async Task<IActionResult> Index()
    {
        var sites = await _siteService.GetAllAsync();
        var model = new ReportsDashboardViewModel
        {
            AvailableSites = sites
        };
        return View(model);
    }

    // GET: Reports/VulnerabilitySummary
    public async Task<IActionResult> VulnerabilitySummary(int? siteId)
    {
        var report = await _reportService.GetVulnerabilitySummaryAsync(siteId);
        var sites = await _siteService.GetAllAsync();

        ViewBag.Sites = sites;
        ViewBag.SelectedSiteId = siteId;

        return View(report);
    }

    // GET: Reports/HostSummary
    public async Task<IActionResult> HostSummary(int? siteId)
    {
        var report = await _reportService.GetHostSummaryAsync(siteId);
        var sites = await _siteService.GetAllAsync();

        ViewBag.Sites = sites;
        ViewBag.SelectedSiteId = siteId;

        return View(report);
    }

    // GET: Reports/Export
    public async Task<IActionResult> Export()
    {
        var sites = await _siteService.GetAllAsync();
        var model = new ExportViewModel
        {
            AvailableSites = sites
        };
        return View(model);
    }

    // POST: Reports/ExportCsv
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ExportCsv(ExportViewModel model)
    {
        var criteria = new VulnerabilityExportCriteria
        {
            SiteId = model.SiteId,
            MinimumSeverity = model.MinimumSeverity,
            Status = model.Status,
            IsExploitable = model.ExploitableOnly ? true : null,
            IncludeRemediated = model.IncludeRemediated
        };

        _logger.LogInformation("User {User} exporting vulnerabilities to CSV", User.Identity?.Name);

        var data = await _reportService.ExportVulnerabilitiesToCsvAsync(criteria);
        var fileName = $"vulnerabilities_{DateTime.Now:yyyyMMdd_HHmmss}.csv";

        return File(data, "text/csv", fileName);
    }

    // POST: Reports/ExportExcel
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ExportExcel(ExportViewModel model)
    {
        var criteria = new VulnerabilityExportCriteria
        {
            SiteId = model.SiteId,
            MinimumSeverity = model.MinimumSeverity,
            Status = model.Status,
            IsExploitable = model.ExploitableOnly ? true : null,
            IncludeRemediated = model.IncludeRemediated
        };

        _logger.LogInformation("User {User} exporting vulnerabilities to Excel", User.Identity?.Name);

        var data = await _reportService.ExportVulnerabilitiesToExcelAsync(criteria);
        var fileName = $"vulnerabilities_{DateTime.Now:yyyyMMdd_HHmmss}.xlsx";

        return File(data, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", fileName);
    }
}
