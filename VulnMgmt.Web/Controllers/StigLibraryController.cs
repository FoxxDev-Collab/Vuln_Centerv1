using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using VulnMgmt.Web.Models.Domain;
using VulnMgmt.Web.Models.ViewModels;
using VulnMgmt.Web.Services;

namespace VulnMgmt.Web.Controllers;

[Authorize]
public class StigLibraryController : Controller
{
    private readonly IStigLibraryService _stigService;
    private readonly ILogger<StigLibraryController> _logger;

    public StigLibraryController(IStigLibraryService stigService, ILogger<StigLibraryController> logger)
    {
        _stigService = stigService;
        _logger = logger;
    }

    // GET: /StigLibrary
    public async Task<IActionResult> Index()
    {
        var benchmarks = await _stigService.GetAllBenchmarksAsync();
        var stats = await _stigService.GetLibraryStatsAsync();
        ViewBag.Stats = stats;
        return View(benchmarks);
    }

    // GET: /StigLibrary/Import
    [Authorize(Policy = "ManagerOrAbove")]
    public IActionResult Import()
    {
        return View();
    }

    // POST: /StigLibrary/Import
    [HttpPost]
    [ValidateAntiForgeryToken]
    [Authorize(Policy = "ManagerOrAbove")]
    public async Task<IActionResult> Import(List<IFormFile> files)
    {
        if (files == null || files.Count == 0)
        {
            TempData["Error"] = "Please select at least one file to upload.";
            return View();
        }

        var allowedExtensions = new[] { ".xml", ".zip" };
        var combinedResult = new StigImportResult { Success = true };

        foreach (var file in files)
        {
            if (file.Length == 0)
            {
                combinedResult.Warnings.Add($"Skipped empty file: {file.FileName}");
                continue;
            }

            var extension = Path.GetExtension(file.FileName).ToLowerInvariant();

            if (!allowedExtensions.Contains(extension))
            {
                combinedResult.Warnings.Add($"Skipped invalid file type: {file.FileName}");
                continue;
            }

            try
            {
                using var stream = file.OpenReadStream();
                StigImportResult result;

                if (extension == ".zip")
                {
                    result = await _stigService.ImportFromZipAsync(stream, file.FileName);
                }
                else
                {
                    result = await _stigService.ImportFromXccdfAsync(stream, file.FileName);
                }

                // Merge results
                combinedResult.FilesProcessed += result.FilesProcessed;
                combinedResult.BenchmarksImported += result.BenchmarksImported;
                combinedResult.VersionsCreated += result.VersionsCreated;
                combinedResult.RulesImported += result.RulesImported;
                combinedResult.ImportedBenchmarks.AddRange(result.ImportedBenchmarks);
                combinedResult.Warnings.AddRange(result.Warnings);
                combinedResult.Errors.AddRange(result.Errors);

                if (!result.Success)
                {
                    combinedResult.Errors.Add($"{file.FileName}: {result.ErrorMessage}");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error importing STIG file {FileName}", file.FileName);
                combinedResult.Errors.Add($"{file.FileName}: {ex.Message}");
            }
        }

        // Set overall success based on whether any files were processed
        combinedResult.Success = combinedResult.FilesProcessed > 0 || combinedResult.ImportedBenchmarks.Any();

        if (!combinedResult.Success && !combinedResult.Errors.Any())
        {
            combinedResult.ErrorMessage = "No valid STIG files were found to import.";
        }

        return View("ImportResult", combinedResult);
    }

    // GET: /StigLibrary/Details/5
    public async Task<IActionResult> Details(int id)
    {
        var benchmark = await _stigService.GetBenchmarkByIdAsync(id);
        if (benchmark == null)
        {
            return NotFound();
        }
        return View(benchmark);
    }

    // GET: /StigLibrary/Version/5
    public async Task<IActionResult> Version(int id, string? search, StigSeverity? severity, int page = 1)
    {
        var version = await _stigService.GetBenchmarkVersionByIdAsync(id);
        if (version == null)
        {
            return NotFound();
        }

        const int pageSize = 50;
        var rules = await _stigService.GetRulesForVersionAsync(id, search, severity);
        var totalRules = rules.Count();

        var pagedRules = rules
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToList();

        ViewBag.Search = search;
        ViewBag.Severity = severity;
        ViewBag.CurrentPage = page;
        ViewBag.TotalPages = (int)Math.Ceiling(totalRules / (double)pageSize);
        ViewBag.TotalRules = totalRules;
        ViewBag.Rules = pagedRules;

        return View(version);
    }

    // GET: /StigLibrary/Rule/5
    public async Task<IActionResult> Rule(int id)
    {
        var rule = await _stigService.GetRuleByIdAsync(id);
        if (rule == null)
        {
            return NotFound();
        }
        return View(rule);
    }

    // POST: /StigLibrary/SetCurrentVersion
    [HttpPost]
    [ValidateAntiForgeryToken]
    [Authorize(Policy = "ManagerOrAbove")]
    public async Task<IActionResult> SetCurrentVersion(int benchmarkId, int versionId)
    {
        try
        {
            await _stigService.SetCurrentVersionAsync(benchmarkId, versionId);
            TempData["Success"] = "Current version updated successfully.";
        }
        catch (Exception ex)
        {
            TempData["Error"] = $"Error updating version: {ex.Message}";
        }
        return RedirectToAction(nameof(Details), new { id = benchmarkId });
    }

    // GET: /StigLibrary/DeleteVersion/5
    [Authorize(Policy = "ManagerOrAbove")]
    public async Task<IActionResult> DeleteVersion(int id)
    {
        var version = await _stigService.GetBenchmarkVersionByIdAsync(id);
        if (version == null)
        {
            return NotFound();
        }
        return View(version);
    }

    // POST: /StigLibrary/DeleteVersion/5
    [HttpPost, ActionName("DeleteVersion")]
    [ValidateAntiForgeryToken]
    [Authorize(Policy = "ManagerOrAbove")]
    public async Task<IActionResult> DeleteVersionConfirmed(int id)
    {
        var version = await _stigService.GetBenchmarkVersionByIdAsync(id);
        if (version == null)
        {
            return NotFound();
        }

        var benchmarkId = version.StigBenchmarkId;

        try
        {
            await _stigService.DeleteVersionAsync(id);
            TempData["Success"] = "Version deleted successfully.";
        }
        catch (InvalidOperationException ex)
        {
            TempData["Error"] = ex.Message;
            return RedirectToAction(nameof(Version), new { id });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error deleting STIG version {VersionId}", id);
            TempData["Error"] = $"Error deleting version: {ex.Message}";
            return RedirectToAction(nameof(Version), new { id });
        }

        return RedirectToAction(nameof(Details), new { id = benchmarkId });
    }

    // GET: /StigLibrary/Delete/5
    [Authorize(Policy = "AdminOnly")]
    public async Task<IActionResult> Delete(int id)
    {
        var benchmark = await _stigService.GetBenchmarkByIdAsync(id);
        if (benchmark == null)
        {
            return NotFound();
        }
        return View(benchmark);
    }

    // POST: /StigLibrary/Delete/5
    [HttpPost, ActionName("Delete")]
    [ValidateAntiForgeryToken]
    [Authorize(Policy = "AdminOnly")]
    public async Task<IActionResult> DeleteConfirmed(int id)
    {
        try
        {
            await _stigService.DeleteBenchmarkAsync(id);
            TempData["Success"] = "STIG benchmark deleted successfully.";
        }
        catch (InvalidOperationException ex)
        {
            TempData["Error"] = ex.Message;
            return RedirectToAction(nameof(Details), new { id });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error deleting STIG benchmark {BenchmarkId}", id);
            TempData["Error"] = $"Error deleting benchmark: {ex.Message}";
            return RedirectToAction(nameof(Details), new { id });
        }

        return RedirectToAction(nameof(Index));
    }
}
