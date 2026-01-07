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
    private readonly INistComplianceExportService _nistExportService;
    private readonly IUserService _userService;
    private readonly ILogger<ReportsController> _logger;

    public ReportsController(
        IReportService reportService,
        ISiteService siteService,
        INistComplianceExportService nistExportService,
        IUserService userService,
        ILogger<ReportsController> logger)
    {
        _reportService = reportService;
        _siteService = siteService;
        _nistExportService = nistExportService;
        _userService = userService;
        _logger = logger;
    }

    private async Task<int?> GetCurrentUserIdAsync()
    {
        var username = User.Identity?.Name;
        if (string.IsNullOrEmpty(username)) return null;
        var user = await _userService.GetByUsernameAsync(username);
        return user?.Id;
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

    // GET: Reports/NistExport
    public async Task<IActionResult> NistExport(int? siteId)
    {
        var sites = await _nistExportService.GetSitesForExportAsync();
        var model = new NistExportViewModel
        {
            Sites = sites,
            SelectedSiteId = siteId
        };

        if (siteId.HasValue)
        {
            model.Preview = await _nistExportService.GetExportPreviewAsync(siteId.Value);
        }

        return View(model);
    }

    // GET: Reports/NistExportPreview (AJAX)
    [HttpGet]
    public async Task<IActionResult> NistExportPreview(int siteId)
    {
        var preview = await _nistExportService.GetExportPreviewAsync(siteId);
        if (preview == null)
        {
            return NotFound();
        }
        return PartialView("_NistExportPreview", preview);
    }

    // POST: Reports/ExportNistJson
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ExportNistJson(int siteId)
    {
        var userId = await GetCurrentUserIdAsync();
        var site = await _siteService.GetByIdAsync(siteId);

        if (site == null)
        {
            TempData["Error"] = "Site not found.";
            return RedirectToAction(nameof(NistExport));
        }

        _logger.LogInformation("User {User} exporting NIST compliance data for site {SiteId} ({SiteName})",
            User.Identity?.Name, siteId, site.Name);

        try
        {
            var data = await _nistExportService.ExportSiteToJsonAsync(siteId, userId);

            // Generate filename with site name (sanitized) and timestamp
            var sanitizedSiteName = string.Join("_", site.Name.Split(Path.GetInvalidFileNameChars()));
            var fileName = $"NIST_Compliance_Export_{sanitizedSiteName}_{DateTime.Now:yyyyMMdd_HHmmss}.json";

            return File(data, "application/json", fileName);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error exporting NIST compliance data for site {SiteId}", siteId);
            TempData["Error"] = "An error occurred while generating the export. Please try again.";
            return RedirectToAction(nameof(NistExport), new { siteId });
        }
    }
}
