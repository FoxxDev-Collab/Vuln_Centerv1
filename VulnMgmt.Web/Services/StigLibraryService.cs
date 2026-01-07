using System.Globalization;
using System.IO.Compression;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using Microsoft.EntityFrameworkCore;
using VulnMgmt.Web.Data;
using VulnMgmt.Web.Models.Domain;

namespace VulnMgmt.Web.Services;

public class StigLibraryService : IStigLibraryService
{
    private readonly ApplicationDbContext _context;
    private readonly ILogger<StigLibraryService> _logger;

    private static readonly XNamespace XccdfNs = "http://checklists.nist.gov/xccdf/1.1";

    public StigLibraryService(ApplicationDbContext context, ILogger<StigLibraryService> logger)
    {
        _context = context;
        _logger = logger;
    }

    #region Benchmark Operations

    public async Task<IEnumerable<StigBenchmark>> GetAllBenchmarksAsync()
    {
        return await _context.StigBenchmarks
            .Include(b => b.CurrentVersion)
            .Include(b => b.Versions)
            .OrderBy(b => b.Title)
            .ToListAsync();
    }

    public async Task<StigBenchmark?> GetBenchmarkByIdAsync(int id)
    {
        return await _context.StigBenchmarks
            .Include(b => b.CurrentVersion)
            .Include(b => b.Versions)
            .FirstOrDefaultAsync(b => b.Id == id);
    }

    public async Task<StigBenchmark?> GetBenchmarkByStigIdAsync(string stigId)
    {
        return await _context.StigBenchmarks
            .Include(b => b.CurrentVersion)
            .Include(b => b.Versions)
            .FirstOrDefaultAsync(b => b.StigId == stigId);
    }

    public async Task<StigBenchmarkVersion?> GetBenchmarkVersionByIdAsync(int id)
    {
        return await _context.StigBenchmarkVersions
            .Include(v => v.StigBenchmark)
            .Include(v => v.Rules)
            .FirstOrDefaultAsync(v => v.Id == id);
    }

    public async Task<IEnumerable<StigBenchmarkVersion>> GetVersionsForBenchmarkAsync(int benchmarkId)
    {
        return await _context.StigBenchmarkVersions
            .Where(v => v.StigBenchmarkId == benchmarkId)
            .OrderByDescending(v => v.ImportDate)
            .ToListAsync();
    }

    public async Task<StigRule?> GetRuleByIdAsync(int id)
    {
        return await _context.StigRules
            .Include(r => r.BenchmarkVersion)
                .ThenInclude(v => v.StigBenchmark)
            .FirstOrDefaultAsync(r => r.Id == id);
    }

    public async Task<IEnumerable<StigRule>> GetRulesForVersionAsync(int versionId, string? searchTerm = null, StigSeverity? severity = null)
    {
        var query = _context.StigRules
            .Where(r => r.BenchmarkVersionId == versionId);

        if (!string.IsNullOrWhiteSpace(searchTerm))
        {
            var term = searchTerm.ToLower();
            query = query.Where(r =>
                r.VulnId.ToLower().Contains(term) ||
                r.RuleId.ToLower().Contains(term) ||
                r.RuleTitle.ToLower().Contains(term) ||
                (r.RuleVersion != null && r.RuleVersion.ToLower().Contains(term)) ||
                (r.CCIs != null && r.CCIs.ToLower().Contains(term)));
        }

        if (severity.HasValue)
        {
            query = query.Where(r => r.Severity == severity.Value);
        }

        return await query
            .OrderBy(r => r.VulnId)
            .ToListAsync();
    }

    #endregion

    #region Import Operations

    public async Task<StigImportResult> ImportFromZipAsync(Stream zipStream, string fileName)
    {
        var result = new StigImportResult { Success = true };

        try
        {
            using var archive = new ZipArchive(zipStream, ZipArchiveMode.Read);
            var xmlFiles = archive.Entries
                .Where(e => e.Name.EndsWith(".xml", StringComparison.OrdinalIgnoreCase) &&
                            e.Name.Contains("xccdf", StringComparison.OrdinalIgnoreCase))
                .ToList();

            // Also check for nested zips
            var nestedZips = archive.Entries
                .Where(e => e.Name.EndsWith(".zip", StringComparison.OrdinalIgnoreCase))
                .ToList();

            if (!xmlFiles.Any() && !nestedZips.Any())
            {
                // Try all XML files if none have xccdf in name
                xmlFiles = archive.Entries
                    .Where(e => e.Name.EndsWith(".xml", StringComparison.OrdinalIgnoreCase))
                    .ToList();
            }

            foreach (var entry in xmlFiles)
            {
                try
                {
                    using var entryStream = entry.Open();
                    using var memStream = new MemoryStream();
                    await entryStream.CopyToAsync(memStream);
                    memStream.Position = 0;

                    var entryResult = await ImportFromXccdfAsync(memStream, entry.Name);
                    MergeResults(result, entryResult);
                }
                catch (Exception ex)
                {
                    result.Warnings.Add($"Failed to process {entry.Name}: {ex.Message}");
                }
            }

            // Process nested zips
            foreach (var zipEntry in nestedZips)
            {
                try
                {
                    using var entryStream = zipEntry.Open();
                    using var memStream = new MemoryStream();
                    await entryStream.CopyToAsync(memStream);
                    memStream.Position = 0;

                    var nestedResult = await ImportFromZipAsync(memStream, zipEntry.Name);
                    MergeResults(result, nestedResult);
                }
                catch (Exception ex)
                {
                    result.Warnings.Add($"Failed to process nested zip {zipEntry.Name}: {ex.Message}");
                }
            }

            result.FilesProcessed = xmlFiles.Count + nestedZips.Count;
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.ErrorMessage = $"Failed to process zip file: {ex.Message}";
            _logger.LogError(ex, "Error processing zip file {FileName}", fileName);
        }

        return result;
    }

    public async Task<StigImportResult> ImportFromXccdfAsync(Stream xmlStream, string fileName)
    {
        var result = new StigImportResult { Success = true };

        try
        {
            var doc = await XDocument.LoadAsync(xmlStream, LoadOptions.None, CancellationToken.None);
            var benchmark = doc.Root;

            if (benchmark == null || benchmark.Name.LocalName != "Benchmark")
            {
                result.Success = false;
                result.ErrorMessage = "Invalid XCCDF file: root element is not Benchmark";
                return result;
            }

            // Extract benchmark info
            var stigId = benchmark.Attribute("id")?.Value ?? "";
            var title = GetElementText(benchmark, "title") ?? stigId;
            var description = GetElementText(benchmark, "description");
            var version = GetElementText(benchmark, "version") ?? "1";
            var releaseInfo = GetPlainText(benchmark, "release-info");
            var release = ExtractReleaseNumber(releaseInfo);
            var benchmarkDate = ExtractBenchmarkDate(releaseInfo);

            if (string.IsNullOrEmpty(stigId))
            {
                result.Success = false;
                result.ErrorMessage = "Invalid XCCDF file: missing benchmark id";
                return result;
            }

            // Find or create benchmark
            var existingBenchmark = await _context.StigBenchmarks
                .Include(b => b.Versions)
                .FirstOrDefaultAsync(b => b.StigId == stigId);

            bool isNewBenchmark = existingBenchmark == null;

            if (existingBenchmark == null)
            {
                existingBenchmark = new StigBenchmark
                {
                    StigId = stigId,
                    Title = title,
                    Description = description,
                    CreatedDate = DateTime.UtcNow,
                    ModifiedDate = DateTime.UtcNow
                };
                _context.StigBenchmarks.Add(existingBenchmark);
                await _context.SaveChangesAsync();
                result.BenchmarksImported++;
            }
            else
            {
                // Update title/description if changed
                existingBenchmark.Title = title;
                existingBenchmark.Description = description;
                existingBenchmark.ModifiedDate = DateTime.UtcNow;
            }

            // Check if this version already exists
            var existingVersion = existingBenchmark.Versions
                .FirstOrDefault(v => v.Version == version && v.Release == release);

            bool isNewVersion = existingVersion == null;

            if (existingVersion != null)
            {
                // Version already exists - skip or update based on preference
                result.Warnings.Add($"Version {version} Release {release} already exists for {stigId}. Skipping.");
                result.ImportedBenchmarks.Add(new ImportedBenchmarkInfo
                {
                    BenchmarkId = existingBenchmark.Id,
                    VersionId = existingVersion.Id,
                    StigId = stigId,
                    Title = title,
                    Version = version,
                    Release = release,
                    RuleCount = existingVersion.RuleCount,
                    IsNewBenchmark = false,
                    IsNewVersion = false
                });
                return result;
            }

            // Create new version
            var newVersion = new StigBenchmarkVersion
            {
                StigBenchmarkId = existingBenchmark.Id,
                Version = version,
                Release = release,
                ReleaseInfo = releaseInfo,
                BenchmarkDate = benchmarkDate,
                FileName = fileName,
                ImportDate = DateTime.UtcNow,
                IsActive = true
            };
            _context.StigBenchmarkVersions.Add(newVersion);
            await _context.SaveChangesAsync();
            result.VersionsCreated++;

            // Mark other versions as not active
            foreach (var oldVersion in existingBenchmark.Versions.Where(v => v.Id != newVersion.Id))
            {
                oldVersion.IsActive = false;
            }

            // Set as current version
            existingBenchmark.CurrentVersionId = newVersion.Id;

            // Parse and import rules
            var groups = benchmark.Descendants(XccdfNs + "Group").ToList();
            var rules = new List<StigRule>();

            foreach (var group in groups)
            {
                var rule = ParseGroup(group, newVersion.Id);
                if (rule != null)
                {
                    rules.Add(rule);
                }
            }

            if (rules.Any())
            {
                _context.StigRules.AddRange(rules);
                newVersion.RuleCount = rules.Count;
                result.RulesImported += rules.Count;
            }

            await _context.SaveChangesAsync();
            result.FilesProcessed++;

            result.ImportedBenchmarks.Add(new ImportedBenchmarkInfo
            {
                BenchmarkId = existingBenchmark.Id,
                VersionId = newVersion.Id,
                StigId = stigId,
                Title = title,
                Version = version,
                Release = release,
                RuleCount = rules.Count,
                IsNewBenchmark = isNewBenchmark,
                IsNewVersion = isNewVersion
            });

            _logger.LogInformation("Imported STIG {StigId} version {Version} release {Release} with {RuleCount} rules",
                stigId, version, release, rules.Count);
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.ErrorMessage = $"Error parsing XCCDF file: {ex.Message}";
            _logger.LogError(ex, "Error importing XCCDF file {FileName}", fileName);
        }

        return result;
    }

    private StigRule? ParseGroup(XElement group, int versionId)
    {
        try
        {
            var vulnId = group.Attribute("id")?.Value ?? "";
            var groupTitle = GetElementText(group, "title");

            var ruleElement = group.Element(XccdfNs + "Rule");
            if (ruleElement == null) return null;

            var ruleId = ruleElement.Attribute("id")?.Value ?? "";
            var severityStr = ruleElement.Attribute("severity")?.Value ?? "medium";
            var weight = ruleElement.Attribute("weight")?.Value;

            var ruleVersion = GetElementText(ruleElement, "version");
            var ruleTitle = GetElementText(ruleElement, "title") ?? "";
            var discussion = GetElementText(ruleElement, "description");
            var fixText = GetElementText(ruleElement, "fixtext");

            // Get check content
            var checkElement = ruleElement.Element(XccdfNs + "check");
            var checkContent = GetElementText(checkElement, "check-content");

            // Get CCIs
            var ccis = ruleElement.Elements(XccdfNs + "ident")
                .Where(i => i.Attribute("system")?.Value?.Contains("cci") == true)
                .Select(i => i.Value)
                .ToList();

            // Get legacy IDs
            var legacyIds = ruleElement.Elements(XccdfNs + "ident")
                .Where(i => i.Attribute("system")?.Value?.Contains("legacy") == true)
                .Select(i => i.Value)
                .ToList();

            return new StigRule
            {
                BenchmarkVersionId = versionId,
                VulnId = vulnId,
                RuleId = ruleId,
                GroupId = vulnId,
                GroupTitle = groupTitle,
                Severity = ParseSeverity(severityStr),
                RuleVersion = ruleVersion,
                RuleTitle = ruleTitle,
                Discussion = discussion,
                CheckContent = checkContent,
                FixText = fixText,
                CCIs = ccis.Any() ? string.Join(",", ccis) : null,
                LegacyIds = legacyIds.Any() ? string.Join(",", legacyIds) : null,
                Weight = decimal.TryParse(weight, out var w) ? w : null
            };
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error parsing group element");
            return null;
        }
    }

    private static StigSeverity ParseSeverity(string severity)
    {
        return severity.ToLower() switch
        {
            "high" => StigSeverity.High,
            "medium" => StigSeverity.Medium,
            "low" => StigSeverity.Low,
            _ => StigSeverity.Medium
        };
    }

    private static string? GetElementText(XElement? parent, string elementName)
    {
        if (parent == null) return null;
        var element = parent.Element(XccdfNs + elementName);
        return element?.Value?.Trim();
    }

    private static string? GetPlainText(XElement? parent, string id)
    {
        if (parent == null) return null;
        var element = parent.Elements(XccdfNs + "plain-text")
            .FirstOrDefault(e => e.Attribute("id")?.Value == id);
        return element?.Value?.Trim();
    }

    private static string? ExtractReleaseNumber(string? releaseInfo)
    {
        if (string.IsNullOrEmpty(releaseInfo)) return null;
        var match = Regex.Match(releaseInfo, @"Release:\s*(\d+)", RegexOptions.IgnoreCase);
        return match.Success ? match.Groups[1].Value : null;
    }

    private static DateTime? ExtractBenchmarkDate(string? releaseInfo)
    {
        if (string.IsNullOrEmpty(releaseInfo)) return null;
        var match = Regex.Match(releaseInfo, @"Benchmark Date:\s*(\d{1,2}\s+\w+\s+\d{4})", RegexOptions.IgnoreCase);
        if (match.Success)
        {
            if (DateTime.TryParseExact(match.Groups[1].Value, "dd MMM yyyy",
                CultureInfo.InvariantCulture, DateTimeStyles.None, out var date))
            {
                return date;
            }
        }
        return null;
    }

    private static void MergeResults(StigImportResult target, StigImportResult source)
    {
        if (!source.Success)
        {
            target.Errors.Add(source.ErrorMessage ?? "Unknown error");
        }
        target.Warnings.AddRange(source.Warnings);
        target.Errors.AddRange(source.Errors);
        target.BenchmarksImported += source.BenchmarksImported;
        target.VersionsCreated += source.VersionsCreated;
        target.RulesImported += source.RulesImported;
        target.ImportedBenchmarks.AddRange(source.ImportedBenchmarks);
    }

    #endregion

    #region Version Management

    public async Task SetCurrentVersionAsync(int benchmarkId, int versionId)
    {
        var benchmark = await _context.StigBenchmarks
            .Include(b => b.Versions)
            .FirstOrDefaultAsync(b => b.Id == benchmarkId);

        if (benchmark == null)
            throw new ArgumentException("Benchmark not found");

        var version = benchmark.Versions.FirstOrDefault(v => v.Id == versionId);
        if (version == null)
            throw new ArgumentException("Version not found for this benchmark");

        // Update active flags
        foreach (var v in benchmark.Versions)
        {
            v.IsActive = v.Id == versionId;
        }

        benchmark.CurrentVersionId = versionId;
        benchmark.ModifiedDate = DateTime.UtcNow;

        await _context.SaveChangesAsync();
    }

    public async Task DeleteVersionAsync(int versionId)
    {
        var version = await _context.StigBenchmarkVersions
            .Include(v => v.StigBenchmark)
            .Include(v => v.Rules)
            .Include(v => v.Checklists)
            .FirstOrDefaultAsync(v => v.Id == versionId);

        if (version == null)
            throw new ArgumentException("Version not found");

        if (version.Checklists.Any())
            throw new InvalidOperationException("Cannot delete version that has checklists. Delete checklists first.");

        var benchmark = version.StigBenchmark;

        // If this is the current version, we need to update the benchmark
        if (benchmark.CurrentVersionId == versionId)
        {
            var otherVersion = await _context.StigBenchmarkVersions
                .Where(v => v.StigBenchmarkId == benchmark.Id && v.Id != versionId)
                .OrderByDescending(v => v.ImportDate)
                .FirstOrDefaultAsync();

            benchmark.CurrentVersionId = otherVersion?.Id;
            if (otherVersion != null)
            {
                otherVersion.IsActive = true;
            }
        }

        _context.StigRules.RemoveRange(version.Rules);
        _context.StigBenchmarkVersions.Remove(version);

        await _context.SaveChangesAsync();
    }

    public async Task DeleteBenchmarkAsync(int benchmarkId)
    {
        var benchmark = await _context.StigBenchmarks
            .Include(b => b.Versions)
                .ThenInclude(v => v.Rules)
            .Include(b => b.Versions)
                .ThenInclude(v => v.Checklists)
            .FirstOrDefaultAsync(b => b.Id == benchmarkId);

        if (benchmark == null)
            throw new ArgumentException("Benchmark not found");

        if (benchmark.Versions.Any(v => v.Checklists.Any()))
            throw new InvalidOperationException("Cannot delete benchmark that has checklists. Delete checklists first.");

        // Delete all rules and versions
        foreach (var version in benchmark.Versions)
        {
            _context.StigRules.RemoveRange(version.Rules);
        }
        _context.StigBenchmarkVersions.RemoveRange(benchmark.Versions);
        _context.StigBenchmarks.Remove(benchmark);

        await _context.SaveChangesAsync();
    }

    #endregion

    #region Statistics

    public async Task<StigLibraryStats> GetLibraryStatsAsync()
    {
        var stats = new StigLibraryStats
        {
            TotalBenchmarks = await _context.StigBenchmarks.CountAsync(),
            TotalVersions = await _context.StigBenchmarkVersions.CountAsync(),
            TotalRules = await _context.StigRules.CountAsync(),
            TotalChecklists = await _context.StigChecklists.CountAsync()
        };

        var rulesBySeverity = await _context.StigRules
            .GroupBy(r => r.Severity)
            .Select(g => new { Severity = g.Key, Count = g.Count() })
            .ToListAsync();

        foreach (var item in rulesBySeverity)
        {
            stats.RulesBySeverity[item.Severity] = item.Count;
        }

        return stats;
    }

    #endregion
}
