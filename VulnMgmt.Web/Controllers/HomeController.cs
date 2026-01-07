using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using VulnMgmt.Web.Data;
using VulnMgmt.Web.Models;
using VulnMgmt.Web.Models.Domain;

namespace VulnMgmt.Web.Controllers;

public class HomeController : Controller
{
    private readonly ILogger<HomeController> _logger;
    private readonly ApplicationDbContext _context;

    public HomeController(ILogger<HomeController> logger, ApplicationDbContext context)
    {
        _logger = logger;
        _context = context;
    }

    public async Task<IActionResult> Index()
    {
        if (User.Identity?.IsAuthenticated == true)
        {
            ViewBag.TotalSites = await _context.Sites.CountAsync();
            ViewBag.TotalHosts = await _context.Hosts.CountAsync();

            var openStatuses = new[] { RemediationStatus.Open, RemediationStatus.InProgress };
            ViewBag.OpenVulns = await _context.HostVulnerabilities
                .Where(v => openStatuses.Contains(v.RemediationStatus))
                .CountAsync();

            ViewBag.CriticalHighVulns = await _context.HostVulnerabilities
                .Where(v => openStatuses.Contains(v.RemediationStatus) &&
                           (v.Severity == Severity.Critical || v.Severity == Severity.High))
                .CountAsync();

            // Severity counts
            ViewBag.CriticalCount = await _context.HostVulnerabilities
                .Where(v => v.Severity == Severity.Critical && openStatuses.Contains(v.RemediationStatus))
                .CountAsync();
            ViewBag.HighCount = await _context.HostVulnerabilities
                .Where(v => v.Severity == Severity.High && openStatuses.Contains(v.RemediationStatus))
                .CountAsync();
            ViewBag.MediumCount = await _context.HostVulnerabilities
                .Where(v => v.Severity == Severity.Medium && openStatuses.Contains(v.RemediationStatus))
                .CountAsync();
            ViewBag.LowCount = await _context.HostVulnerabilities
                .Where(v => v.Severity == Severity.Low && openStatuses.Contains(v.RemediationStatus))
                .CountAsync();
            ViewBag.InfoCount = await _context.HostVulnerabilities
                .Where(v => v.Severity == Severity.Info && openStatuses.Contains(v.RemediationStatus))
                .CountAsync();

            // Recent imports
            ViewBag.RecentImports = await _context.ScanImports
                .Include(s => s.Site)
                .OrderByDescending(s => s.ImportDate)
                .Take(5)
                .Select(s => new
                {
                    s.ImportDate,
                    SiteName = s.Site.Name,
                    s.VulnerabilitiesImported
                })
                .ToListAsync();

            // STIG data
            ViewBag.TotalStigChecklists = await _context.StigChecklists.CountAsync();
            ViewBag.StigOpenFindings = await _context.StigChecklists.SumAsync(c => c.OpenCount);
            ViewBag.StigNotReviewedCount = await _context.StigChecklists.SumAsync(c => c.NotReviewedCount);
            ViewBag.StigNotAFindingCount = await _context.StigChecklists.SumAsync(c => c.NotAFindingCount);
            ViewBag.StigNotApplicableCount = await _context.StigChecklists.SumAsync(c => c.NotApplicableCount);
        }

        return View();
    }

    public IActionResult Privacy()
    {
        return View();
    }

    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error()
    {
        return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
    }
}
