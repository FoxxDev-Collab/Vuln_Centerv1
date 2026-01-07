using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using VulnMgmt.Web.Data;
using VulnMgmt.Web.Models.Domain;
using VulnMgmt.Web.Models.ViewModels;
using VulnMgmt.Web.Services;
using DomainHost = VulnMgmt.Web.Models.Domain.Host;

namespace VulnMgmt.Web.Controllers;

[Authorize]
public class HostController : Controller
{
    private readonly IHostService _hostService;
    private readonly ISiteService _siteService;
    private readonly ApplicationDbContext _context;
    private readonly ILogger<HostController> _logger;

    public HostController(IHostService hostService, ISiteService siteService, ApplicationDbContext context, ILogger<HostController> logger)
    {
        _hostService = hostService;
        _siteService = siteService;
        _context = context;
        _logger = logger;
    }

    public async Task<IActionResult> Index(int? siteId, string? search, HostStatus? status)
    {
        var query = _context.Hosts.Include(h => h.Site).AsQueryable();

        if (siteId.HasValue)
        {
            query = query.Where(h => h.SiteId == siteId.Value);
        }

        if (!string.IsNullOrEmpty(search))
        {
            search = search.ToLower();
            query = query.Where(h =>
                (h.DisplayName != null && h.DisplayName.ToLower().Contains(search)) ||
                (h.DNSName != null && h.DNSName.ToLower().Contains(search)) ||
                (h.NetBIOSName != null && h.NetBIOSName.ToLower().Contains(search)) ||
                (h.LastKnownIPAddress != null && h.LastKnownIPAddress.Contains(search)));
        }

        if (status.HasValue)
        {
            query = query.Where(h => h.Status == status.Value);
        }

        var hosts = await query
            .Select(h => new HostIndexItem
            {
                Id = h.Id,
                DisplayName = h.DisplayName ?? h.DNSName ?? h.NetBIOSName ?? "Unknown",
                DNSName = h.DNSName,
                LastKnownIPAddress = h.LastKnownIPAddress,
                OperatingSystem = h.OperatingSystem,
                SiteName = h.Site.Name,
                SiteId = h.SiteId,
                Status = h.Status,
                AssetType = h.AssetType,
                OpenVulnCount = h.Vulnerabilities.Count(v => v.RemediationStatus == RemediationStatus.Open || v.RemediationStatus == RemediationStatus.InProgress),
                CriticalCount = h.Vulnerabilities.Count(v => v.Severity == Severity.Critical && (v.RemediationStatus == RemediationStatus.Open || v.RemediationStatus == RemediationStatus.InProgress)),
                HighCount = h.Vulnerabilities.Count(v => v.Severity == Severity.High && (v.RemediationStatus == RemediationStatus.Open || v.RemediationStatus == RemediationStatus.InProgress)),
                LastScanDate = h.LastScanDate,
                StigChecklistCount = _context.StigChecklists.Count(c => c.HostId == h.Id),
                StigOpenCount = _context.StigChecklists.Where(c => c.HostId == h.Id).Sum(c => c.OpenCount)
            })
            .OrderBy(h => h.SiteName)
            .ThenBy(h => h.DisplayName)
            .ToListAsync();

        var model = new HostIndexViewModel
        {
            Hosts = hosts,
            SiteId = siteId,
            SearchTerm = search,
            StatusFilter = status
        };

        if (siteId.HasValue)
        {
            var site = await _siteService.GetByIdAsync(siteId.Value);
            model.SiteName = site?.Name;
        }

        return View(model);
    }

    public async Task<IActionResult> Details(int id)
    {
        var host = await _hostService.GetByIdWithVulnerabilitiesAsync(id);
        if (host == null)
        {
            return NotFound();
        }

        var summary = await _hostService.GetHostVulnSummaryAsync(id);

        var vulns = host.Vulnerabilities
            .OrderByDescending(v => v.Severity)
            .ThenBy(v => v.RemediationStatus)
            .ThenBy(v => v.PluginName)
            .Select(v => new VulnerabilityListItem
            {
                Id = v.Id,
                PluginId = v.PluginId,
                PluginName = v.PluginName,
                Family = v.Family,
                Severity = v.Severity,
                CVE = v.CVE,
                Port = v.Port,
                Protocol = v.Protocol,
                RemediationStatus = v.RemediationStatus,
                LastObserved = v.LastObserved,
                FirstDiscovered = v.FirstDiscovered,
                IsExploitable = v.IsExploitable
            })
            .ToList();

        return View(new HostDetailsViewModel
        {
            Host = host,
            Summary = summary,
            Vulnerabilities = vulns
        });
    }

    [Authorize(Roles = "Admin,ISSM")]
    public async Task<IActionResult> Create(int? siteId)
    {
        var sites = await _siteService.GetAllAsync();

        var model = new HostCreateViewModel
        {
            SiteId = siteId ?? 0,
            Sites = new SelectList(sites, "Id", "Name", siteId)
        };

        if (siteId.HasValue)
        {
            var site = await _siteService.GetByIdAsync(siteId.Value);
            model.SiteName = site?.Name;
        }

        return View(model);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    [Authorize(Roles = "Admin,ISSM")]
    public async Task<IActionResult> Create(HostCreateViewModel model)
    {
        if (model.SiteId == 0)
        {
            ModelState.AddModelError("SiteId", "Please select a site.");
        }

        if (string.IsNullOrEmpty(model.DNSName) && string.IsNullOrEmpty(model.NetBIOSName) && string.IsNullOrEmpty(model.DisplayName))
        {
            ModelState.AddModelError(string.Empty, "Please provide at least a DNS Name, NetBIOS Name, or Display Name.");
        }

        if (!ModelState.IsValid)
        {
            var sites = await _siteService.GetAllAsync();
            model.Sites = new SelectList(sites, "Id", "Name", model.SiteId);
            return View(model);
        }

        var host = new DomainHost
        {
            SiteId = model.SiteId,
            DNSName = model.DNSName,
            NetBIOSName = model.NetBIOSName,
            DisplayName = model.DisplayName ?? model.DNSName ?? model.NetBIOSName,
            Description = model.Description,
            OperatingSystem = model.OperatingSystem,
            OSVersion = model.OSVersion,
            LastKnownIPAddress = model.LastKnownIPAddress,
            LastKnownMACAddress = model.LastKnownMACAddress,
            AssetType = model.AssetType,
            AssetTag = model.AssetTag,
            SerialNumber = model.SerialNumber,
            Status = model.Status
        };

        await _hostService.CreateAsync(host);
        _logger.LogInformation("Host {HostName} created by {User}", host.DisplayName, User.Identity?.Name);

        TempData["Success"] = $"Host '{host.DisplayName}' created successfully.";
        return RedirectToAction(nameof(Details), new { id = host.Id });
    }

    [Authorize(Roles = "Admin,ISSM")]
    public async Task<IActionResult> Edit(int id)
    {
        var host = await _hostService.GetByIdAsync(id);
        if (host == null)
        {
            return NotFound();
        }

        var sites = await _siteService.GetAllAsync();

        var model = new HostEditViewModel
        {
            Id = host.Id,
            SiteId = host.SiteId,
            SiteName = host.Site?.Name,
            DNSName = host.DNSName,
            NetBIOSName = host.NetBIOSName,
            DisplayName = host.DisplayName,
            Description = host.Description,
            OperatingSystem = host.OperatingSystem,
            OSVersion = host.OSVersion,
            LastKnownIPAddress = host.LastKnownIPAddress,
            LastKnownMACAddress = host.LastKnownMACAddress,
            AssetType = host.AssetType,
            AssetTag = host.AssetTag,
            SerialNumber = host.SerialNumber,
            Status = host.Status,
            CreatedDate = host.CreatedDate,
            LastScanDate = host.LastScanDate,
            LastScanVulnCount = host.LastScanVulnCount,
            Sites = new SelectList(sites, "Id", "Name", host.SiteId)
        };

        return View(model);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    [Authorize(Roles = "Admin,ISSM")]
    public async Task<IActionResult> Edit(int id, HostEditViewModel model)
    {
        if (id != model.Id)
        {
            return BadRequest();
        }

        if (string.IsNullOrEmpty(model.DNSName) && string.IsNullOrEmpty(model.NetBIOSName) && string.IsNullOrEmpty(model.DisplayName))
        {
            ModelState.AddModelError(string.Empty, "Please provide at least a DNS Name, NetBIOS Name, or Display Name.");
        }

        if (!ModelState.IsValid)
        {
            var sites = await _siteService.GetAllAsync();
            model.Sites = new SelectList(sites, "Id", "Name", model.SiteId);
            return View(model);
        }

        var host = await _hostService.GetByIdAsync(id);
        if (host == null)
        {
            return NotFound();
        }

        host.SiteId = model.SiteId;
        host.DNSName = model.DNSName;
        host.NetBIOSName = model.NetBIOSName;
        host.DisplayName = model.DisplayName ?? model.DNSName ?? model.NetBIOSName;
        host.Description = model.Description;
        host.OperatingSystem = model.OperatingSystem;
        host.OSVersion = model.OSVersion;
        host.LastKnownIPAddress = model.LastKnownIPAddress;
        host.LastKnownMACAddress = model.LastKnownMACAddress;
        host.AssetType = model.AssetType;
        host.AssetTag = model.AssetTag;
        host.SerialNumber = model.SerialNumber;
        host.Status = model.Status;

        await _hostService.UpdateAsync(host);
        _logger.LogInformation("Host {HostName} updated by {User}", host.DisplayName, User.Identity?.Name);

        TempData["Success"] = $"Host '{host.DisplayName}' updated successfully.";
        return RedirectToAction(nameof(Details), new { id = host.Id });
    }

    [Authorize(Roles = "Admin,ISSM")]
    public async Task<IActionResult> Delete(int id)
    {
        var host = await _hostService.GetByIdWithVulnerabilitiesAsync(id);
        if (host == null)
        {
            return NotFound();
        }

        return View(host);
    }

    [HttpPost, ActionName("Delete")]
    [ValidateAntiForgeryToken]
    [Authorize(Roles = "Admin,ISSM")]
    public async Task<IActionResult> DeleteConfirmed(int id)
    {
        var host = await _hostService.GetByIdAsync(id);
        if (host == null)
        {
            return NotFound();
        }

        var hostName = host.DisplayName;
        var siteId = host.SiteId;

        await _hostService.DeleteAsync(id);
        _logger.LogInformation("Host {HostName} deleted by {User}", hostName, User.Identity?.Name);

        TempData["Success"] = $"Host '{hostName}' deleted successfully.";
        return RedirectToAction("Details", "Site", new { id = siteId });
    }
}
