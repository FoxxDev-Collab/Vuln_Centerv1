using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using VulnMgmt.Web.Models.ViewModels;
using VulnMgmt.Web.Services;

namespace VulnMgmt.Web.Controllers;

[Authorize(Policy = "UserOrAbove")]
public class ScanImportController : Controller
{
    private readonly IScanImportService _importService;
    private readonly ISiteService _siteService;
    private readonly IUserService _userService;
    private readonly ILogger<ScanImportController> _logger;

    public ScanImportController(
        IScanImportService importService,
        ISiteService siteService,
        IUserService userService,
        ILogger<ScanImportController> logger)
    {
        _importService = importService;
        _siteService = siteService;
        _userService = userService;
        _logger = logger;
    }

    // GET: ScanImport
    public async Task<IActionResult> Index(int? siteId)
    {
        var imports = await _importService.GetAllImportsAsync(siteId);
        var sites = await _siteService.GetAllAsync();

        var model = new ScanImportListViewModel
        {
            Imports = imports,
            FilterSiteId = siteId,
            AvailableSites = sites
        };

        return View(model);
    }

    // GET: ScanImport/Upload
    public async Task<IActionResult> Upload()
    {
        var sites = await _siteService.GetAllAsync();
        var model = new ScanUploadViewModel
        {
            AvailableSites = sites
        };
        return View(model);
    }

    // POST: ScanImport/Upload
    [HttpPost]
    [ValidateAntiForgeryToken]
    [RequestSizeLimit(100_000_000)] // 100 MB limit
    public async Task<IActionResult> Upload(ScanUploadViewModel model)
    {
        var sites = await _siteService.GetAllAsync();
        model.AvailableSites = sites;

        if (model.File == null || model.File.Length == 0)
        {
            ModelState.AddModelError("File", "Please select a CSV file to upload.");
            return View(model);
        }

        // Validate file extension
        var extension = Path.GetExtension(model.File.FileName).ToLowerInvariant();
        if (extension != ".csv")
        {
            ModelState.AddModelError("File", "Only CSV files are accepted for scan import.");
            return View(model);
        }

        if (!ModelState.IsValid)
        {
            return View(model);
        }

        // Get current user ID
        int? userId = null;
        if (User.Identity?.Name != null)
        {
            var user = await _userService.GetByUsernameAsync(User.Identity.Name);
            userId = user?.Id;
        }

        _logger.LogInformation("User {User} uploading scan file {FileName} for site {SiteId}",
            User.Identity?.Name, model.File.FileName, model.SiteId);

        using var stream = model.File.OpenReadStream();
        var result = await _importService.ImportNessusCsvAsync(
            stream,
            model.File.FileName,
            model.SiteId,
            userId,
            model.UpdateExisting,
            model.Notes);

        if (result.Success)
        {
            TempData["Success"] = result.Message;
        }
        else
        {
            TempData["Error"] = "Import failed. See details below.";
        }

        return View("UploadResult", result);
    }

    // GET: ScanImport/Details/5
    public async Task<IActionResult> Details(int id)
    {
        var import = await _importService.GetImportByIdAsync(id);
        if (import == null)
        {
            return NotFound();
        }

        return View(import);
    }

    // GET: ScanImport/Delete/5
    [Authorize(Policy = "ManagerOrAbove")]
    public async Task<IActionResult> Delete(int id)
    {
        var import = await _importService.GetImportByIdAsync(id);
        if (import == null)
        {
            return NotFound();
        }

        return View(import);
    }

    // POST: ScanImport/Delete/5
    [HttpPost, ActionName("Delete")]
    [ValidateAntiForgeryToken]
    [Authorize(Policy = "ManagerOrAbove")]
    public async Task<IActionResult> DeleteConfirmed(int id)
    {
        var import = await _importService.GetImportByIdAsync(id);
        if (import == null)
        {
            return NotFound();
        }

        _logger.LogInformation("User {User} deleting scan import {Id} ({FileName})",
            User.Identity?.Name, id, import.FileName);

        await _importService.DeleteImportAsync(id);
        TempData["Success"] = $"Import record '{import.FileName}' deleted successfully.";

        return RedirectToAction(nameof(Index));
    }
}
