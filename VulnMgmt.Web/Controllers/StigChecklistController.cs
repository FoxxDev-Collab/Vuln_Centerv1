using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using VulnMgmt.Web.Models.Domain;
using VulnMgmt.Web.Services;

namespace VulnMgmt.Web.Controllers;

[Authorize]
public class StigChecklistController : Controller
{
    private readonly IStigChecklistService _checklistService;
    private readonly IStigLibraryService _libraryService;
    private readonly IHostService _hostService;
    private readonly IUserService _userService;
    private readonly ILogger<StigChecklistController> _logger;

    public StigChecklistController(
        IStigChecklistService checklistService,
        IStigLibraryService libraryService,
        IHostService hostService,
        IUserService userService,
        ILogger<StigChecklistController> logger)
    {
        _checklistService = checklistService;
        _libraryService = libraryService;
        _hostService = hostService;
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

    // GET: /StigChecklist
    public async Task<IActionResult> Index()
    {
        var checklists = await _checklistService.GetAllChecklistsAsync();
        return View(checklists);
    }

    // GET: /StigChecklist/Create
    [Authorize(Policy = "CanEdit")]
    public async Task<IActionResult> Create(int? hostId)
    {
        var hosts = await _hostService.GetAllAsync();
        var benchmarks = await _libraryService.GetAllBenchmarksAsync();

        ViewBag.Hosts = new SelectList(hosts, "Id", "DisplayName", hostId);
        ViewBag.Benchmarks = benchmarks
            .Where(b => b.CurrentVersion != null)
            .Select(b => new SelectListItem
            {
                Value = b.CurrentVersion!.Id.ToString(),
                Text = $"{b.Title} (V{b.CurrentVersion.Version}R{b.CurrentVersion.Release})"
            });
        ViewBag.SelectedHostId = hostId;

        return View();
    }

    // POST: /StigChecklist/Create
    [HttpPost]
    [ValidateAntiForgeryToken]
    [Authorize(Policy = "CanEdit")]
    public async Task<IActionResult> Create(int hostId, int benchmarkVersionId, string? title)
    {
        try
        {
            var userId = await GetCurrentUserIdAsync();
            var checklist = await _checklistService.CreateChecklistAsync(hostId, benchmarkVersionId, title, userId);
            TempData["Success"] = "Checklist created successfully.";
            return RedirectToAction(nameof(Details), new { id = checklist.Id });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error creating checklist for host {HostId}", hostId);
            TempData["Error"] = $"Error creating checklist: {ex.Message}";
            return RedirectToAction(nameof(Create), new { hostId });
        }
    }

    // GET: /StigChecklist/Details/5
    public async Task<IActionResult> Details(int id, string? search, StigSeverity? severity, StigResultStatus? status, int page = 1)
    {
        var checklist = await _checklistService.GetChecklistByIdAsync(id);
        if (checklist == null)
        {
            return NotFound();
        }

        const int pageSize = 50;
        var results = await _checklistService.GetResultsForChecklistAsync(id, search, severity, status);
        var totalResults = results.Count();

        var pagedResults = results
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToList();

        ViewBag.Search = search;
        ViewBag.Severity = severity;
        ViewBag.Status = status;
        ViewBag.CurrentPage = page;
        ViewBag.TotalPages = (int)Math.Ceiling(totalResults / (double)pageSize);
        ViewBag.TotalResults = totalResults;
        ViewBag.Results = pagedResults;

        return View(checklist);
    }

    // GET: /StigChecklist/Result/5
    public async Task<IActionResult> Result(int id)
    {
        var result = await _checklistService.GetResultByIdAsync(id);
        if (result == null)
        {
            return NotFound();
        }
        return View(result);
    }

    // POST: /StigChecklist/UpdateResult
    [HttpPost]
    [ValidateAntiForgeryToken]
    [Authorize(Policy = "CanEdit")]
    public async Task<IActionResult> UpdateResult(int id, StigResultStatus status, string? findingDetails, string? comments)
    {
        try
        {
            var userId = await GetCurrentUserIdAsync();
            await _checklistService.UpdateResultAsync(id, status, findingDetails, comments, userId);
            TempData["Success"] = "Result updated successfully.";
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error updating result {ResultId}", id);
            TempData["Error"] = $"Error updating result: {ex.Message}";
        }

        var result = await _checklistService.GetResultByIdAsync(id);
        return RedirectToAction(nameof(Details), new { id = result?.ChecklistId });
    }

    // GET: /StigChecklist/Import
    [Authorize(Policy = "CanEdit")]
    public async Task<IActionResult> Import(int? hostId)
    {
        var hosts = await _hostService.GetAllAsync();
        ViewBag.Hosts = new SelectList(hosts, "Id", "DisplayName", hostId);
        ViewBag.SelectedHostId = hostId;
        return View();
    }

    // POST: /StigChecklist/Import
    [HttpPost]
    [ValidateAntiForgeryToken]
    [Authorize(Policy = "CanEdit")]
    public async Task<IActionResult> Import(int hostId, IFormFile file)
    {
        if (file == null || file.Length == 0)
        {
            TempData["Error"] = "Please select a file to upload.";
            return RedirectToAction(nameof(Import), new { hostId });
        }

        var extension = Path.GetExtension(file.FileName).ToLowerInvariant();
        var allowedExtensions = new[] { ".cklb", ".json", ".xml" };

        if (!allowedExtensions.Contains(extension))
        {
            TempData["Error"] = "Invalid file type. Please upload an XCCDF results (.xml), CKLB (.cklb), or JSON file.";
            return RedirectToAction(nameof(Import), new { hostId });
        }

        try
        {
            var userId = await GetCurrentUserIdAsync();
            using var stream = file.OpenReadStream();
            ChecklistImportResult result;

            if (extension == ".xml")
            {
                result = await _checklistService.ImportFromXccdfResultsAsync(stream, hostId, file.FileName, userId);
            }
            else
            {
                result = await _checklistService.ImportFromCklbAsync(stream, hostId, file.FileName, userId);
            }

            return View("ImportResult", result);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error importing file {FileName}", file.FileName);
            TempData["Error"] = $"Error importing file: {ex.Message}";
            return RedirectToAction(nameof(Import), new { hostId });
        }
    }

    // GET: /StigChecklist/Export/5
    public async Task<IActionResult> Export(int id)
    {
        try
        {
            var checklist = await _checklistService.GetChecklistByIdAsync(id);
            if (checklist == null)
            {
                return NotFound();
            }

            var bytes = await _checklistService.ExportToCklbAsync(id);
            var fileName = $"{checklist.Host.DisplayName ?? checklist.Host.DNSName}_{checklist.BenchmarkVersion.StigBenchmark.StigId}.cklb";

            return File(bytes, "application/json", fileName);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error exporting checklist {ChecklistId}", id);
            TempData["Error"] = $"Error exporting checklist: {ex.Message}";
            return RedirectToAction(nameof(Details), new { id });
        }
    }

    // GET: /StigChecklist/Delete/5
    [Authorize(Policy = "ManagerOrAbove")]
    public async Task<IActionResult> Delete(int id)
    {
        var checklist = await _checklistService.GetChecklistByIdAsync(id);
        if (checklist == null)
        {
            return NotFound();
        }
        return View(checklist);
    }

    // POST: /StigChecklist/Delete/5
    [HttpPost, ActionName("Delete")]
    [ValidateAntiForgeryToken]
    [Authorize(Policy = "ManagerOrAbove")]
    public async Task<IActionResult> DeleteConfirmed(int id)
    {
        try
        {
            await _checklistService.DeleteChecklistAsync(id);
            TempData["Success"] = "Checklist deleted successfully.";
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error deleting checklist {ChecklistId}", id);
            TempData["Error"] = $"Error deleting checklist: {ex.Message}";
            return RedirectToAction(nameof(Details), new { id });
        }

        return RedirectToAction(nameof(Index));
    }
}
