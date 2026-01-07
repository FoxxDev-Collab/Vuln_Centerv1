using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using VulnMgmt.Web.Data;
using VulnMgmt.Web.Models.Domain;
using VulnMgmt.Web.Models.ViewModels;
using VulnMgmt.Web.Services;

namespace VulnMgmt.Web.Controllers;

[Authorize]
public class SiteController : Controller
{
    private readonly ISiteService _siteService;
    private readonly ApplicationDbContext _context;
    private readonly ILogger<SiteController> _logger;

    public SiteController(ISiteService siteService, ApplicationDbContext context, ILogger<SiteController> logger)
    {
        _siteService = siteService;
        _context = context;
        _logger = logger;
    }

    public async Task<IActionResult> Index()
    {
        var sites = await _context.Sites
            .Select(s => new SiteListItem
            {
                Id = s.Id,
                Name = s.Name,
                OrganizationName = s.OrganizationName,
                Location = s.Location,
                IsActive = s.IsActive,
                HostCount = s.Hosts.Count,
                VulnCount = s.Hosts.SelectMany(h => h.Vulnerabilities)
                    .Count(v => v.RemediationStatus == RemediationStatus.Open || v.RemediationStatus == RemediationStatus.InProgress),
                CriticalHighCount = s.Hosts.SelectMany(h => h.Vulnerabilities)
                    .Count(v => (v.RemediationStatus == RemediationStatus.Open || v.RemediationStatus == RemediationStatus.InProgress)
                        && (v.Severity == Severity.Critical || v.Severity == Severity.High)),
                LastScanDate = s.Hosts.Max(h => h.LastScanDate),
                StigChecklistCount = _context.StigChecklists.Count(c => s.Hosts.Select(h => h.Id).Contains(c.HostId)),
                StigOpenCount = _context.StigChecklists.Where(c => s.Hosts.Select(h => h.Id).Contains(c.HostId)).Sum(c => c.OpenCount)
            })
            .OrderBy(s => s.Name)
            .ToListAsync();

        return View(new SiteListViewModel { Sites = sites });
    }

    public async Task<IActionResult> Details(int id)
    {
        var site = await _siteService.GetByIdWithHostsAsync(id);
        if (site == null)
        {
            return NotFound();
        }

        var summary = await _siteService.GetSiteSummaryAsync(id);

        var hosts = await _context.Hosts
            .Where(h => h.SiteId == id)
            .Select(h => new HostListItem
            {
                Id = h.Id,
                DisplayName = h.DisplayName ?? h.DNSName ?? h.NetBIOSName ?? "Unknown",
                DNSName = h.DNSName,
                LastKnownIPAddress = h.LastKnownIPAddress,
                OperatingSystem = h.OperatingSystem,
                Status = h.Status,
                VulnCount = h.Vulnerabilities.Count(v => v.RemediationStatus == RemediationStatus.Open || v.RemediationStatus == RemediationStatus.InProgress),
                CriticalCount = h.Vulnerabilities.Count(v => v.Severity == Severity.Critical && (v.RemediationStatus == RemediationStatus.Open || v.RemediationStatus == RemediationStatus.InProgress)),
                HighCount = h.Vulnerabilities.Count(v => v.Severity == Severity.High && (v.RemediationStatus == RemediationStatus.Open || v.RemediationStatus == RemediationStatus.InProgress)),
                LastScanDate = h.LastScanDate
            })
            .OrderBy(h => h.DisplayName)
            .ToListAsync();

        return View(new SiteDetailsViewModel
        {
            Site = site,
            Summary = summary,
            Hosts = hosts
        });
    }

    [Authorize(Roles = "Admin,ISSM")]
    public IActionResult Create()
    {
        return View(new SiteCreateViewModel());
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    [Authorize(Roles = "Admin,ISSM")]
    public async Task<IActionResult> Create(SiteCreateViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var site = new Site
        {
            Name = model.Name,
            Description = model.Description,
            Location = model.Location,
            OrganizationName = model.OrganizationName,
            POCName = model.POCName,
            POCEmail = model.POCEmail,
            POCPhone = model.POCPhone,
            IsActive = model.IsActive
        };

        await _siteService.CreateAsync(site);
        _logger.LogInformation("Site {SiteName} created by {User}", site.Name, User.Identity?.Name);

        TempData["Success"] = $"Site '{site.Name}' created successfully.";
        return RedirectToAction(nameof(Details), new { id = site.Id });
    }

    [Authorize(Roles = "Admin,ISSM")]
    public async Task<IActionResult> Edit(int id)
    {
        var site = await _siteService.GetByIdAsync(id);
        if (site == null)
        {
            return NotFound();
        }

        var model = new SiteEditViewModel
        {
            Id = site.Id,
            Name = site.Name,
            Description = site.Description,
            Location = site.Location,
            OrganizationName = site.OrganizationName,
            POCName = site.POCName,
            POCEmail = site.POCEmail,
            POCPhone = site.POCPhone,
            IsActive = site.IsActive,
            CreatedDate = site.CreatedDate
        };

        return View(model);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    [Authorize(Roles = "Admin,ISSM")]
    public async Task<IActionResult> Edit(int id, SiteEditViewModel model)
    {
        if (id != model.Id)
        {
            return BadRequest();
        }

        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var site = await _siteService.GetByIdAsync(id);
        if (site == null)
        {
            return NotFound();
        }

        site.Name = model.Name;
        site.Description = model.Description;
        site.Location = model.Location;
        site.OrganizationName = model.OrganizationName;
        site.POCName = model.POCName;
        site.POCEmail = model.POCEmail;
        site.POCPhone = model.POCPhone;
        site.IsActive = model.IsActive;

        await _siteService.UpdateAsync(site);
        _logger.LogInformation("Site {SiteName} updated by {User}", site.Name, User.Identity?.Name);

        TempData["Success"] = $"Site '{site.Name}' updated successfully.";
        return RedirectToAction(nameof(Details), new { id = site.Id });
    }

    [Authorize(Roles = "Admin,ISSM")]
    public async Task<IActionResult> Delete(int id)
    {
        var site = await _siteService.GetByIdWithHostsAsync(id);
        if (site == null)
        {
            return NotFound();
        }

        return View(site);
    }

    [HttpPost, ActionName("Delete")]
    [ValidateAntiForgeryToken]
    [Authorize(Roles = "Admin,ISSM")]
    public async Task<IActionResult> DeleteConfirmed(int id)
    {
        var site = await _siteService.GetByIdAsync(id);
        if (site == null)
        {
            return NotFound();
        }

        var siteName = site.Name;
        await _siteService.DeleteAsync(id);
        _logger.LogInformation("Site {SiteName} deleted by {User}", siteName, User.Identity?.Name);

        TempData["Success"] = $"Site '{siteName}' deleted successfully.";
        return RedirectToAction(nameof(Index));
    }
}
