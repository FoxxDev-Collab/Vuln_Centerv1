using System.Text.Json;
using System.Xml.Linq;
using Microsoft.EntityFrameworkCore;
using VulnMgmt.Web.Data;
using VulnMgmt.Web.Models.Domain;

namespace VulnMgmt.Web.Services;

public class StigChecklistService : IStigChecklistService
{
    private readonly ApplicationDbContext _context;
    private readonly ILogger<StigChecklistService> _logger;

    public StigChecklistService(ApplicationDbContext context, ILogger<StigChecklistService> logger)
    {
        _context = context;
        _logger = logger;
    }

    #region Checklist Operations

    public async Task<IEnumerable<StigChecklist>> GetAllChecklistsAsync()
    {
        return await _context.StigChecklists
            .Include(c => c.Host)
                .ThenInclude(h => h.Site)
            .Include(c => c.BenchmarkVersion)
                .ThenInclude(v => v.StigBenchmark)
            .OrderByDescending(c => c.LastModifiedDate)
            .ToListAsync();
    }

    public async Task<IEnumerable<StigChecklist>> GetChecklistsForHostAsync(int hostId)
    {
        return await _context.StigChecklists
            .Include(c => c.BenchmarkVersion)
                .ThenInclude(v => v.StigBenchmark)
            .Where(c => c.HostId == hostId)
            .OrderByDescending(c => c.LastModifiedDate)
            .ToListAsync();
    }

    public async Task<StigChecklist?> GetChecklistByIdAsync(int id)
    {
        return await _context.StigChecklists
            .Include(c => c.Host)
                .ThenInclude(h => h.Site)
            .Include(c => c.BenchmarkVersion)
                .ThenInclude(v => v.StigBenchmark)
            .Include(c => c.Results)
                .ThenInclude(r => r.StigRule)
            .Include(c => c.CreatedBy)
            .Include(c => c.LastModifiedBy)
            .FirstOrDefaultAsync(c => c.Id == id);
    }

    public async Task<StigChecklist> CreateChecklistAsync(int hostId, int benchmarkVersionId, string? title, int? userId)
    {
        var host = await _context.Hosts.FindAsync(hostId)
            ?? throw new ArgumentException("Host not found");

        var version = await _context.StigBenchmarkVersions
            .Include(v => v.StigBenchmark)
            .Include(v => v.Rules)
            .FirstOrDefaultAsync(v => v.Id == benchmarkVersionId)
            ?? throw new ArgumentException("Benchmark version not found");

        var checklist = new StigChecklist
        {
            HostId = hostId,
            BenchmarkVersionId = benchmarkVersionId,
            Title = title ?? $"{version.StigBenchmark.Title} - {host.DisplayName ?? host.DNSName}",
            Status = ChecklistStatus.Draft,
            CreatedById = userId,
            LastModifiedById = userId,
            CreatedDate = DateTime.UtcNow,
            LastModifiedDate = DateTime.UtcNow
        };

        _context.StigChecklists.Add(checklist);
        await _context.SaveChangesAsync();

        // Create result entries for all rules
        var results = version.Rules.Select(rule => new StigChecklistResult
        {
            ChecklistId = checklist.Id,
            StigRuleId = rule.Id,
            Status = StigResultStatus.NotReviewed,
            LastModifiedDate = DateTime.UtcNow
        }).ToList();

        _context.StigChecklistResults.AddRange(results);
        checklist.NotReviewedCount = results.Count;
        await _context.SaveChangesAsync();

        _logger.LogInformation("Created checklist {ChecklistId} for host {HostId} with benchmark {BenchmarkVersionId}",
            checklist.Id, hostId, benchmarkVersionId);

        return checklist;
    }

    public async Task DeleteChecklistAsync(int id)
    {
        var checklist = await _context.StigChecklists
            .Include(c => c.Results)
            .FirstOrDefaultAsync(c => c.Id == id)
            ?? throw new ArgumentException("Checklist not found");

        _context.StigChecklistResults.RemoveRange(checklist.Results);
        _context.StigChecklists.Remove(checklist);
        await _context.SaveChangesAsync();

        _logger.LogInformation("Deleted checklist {ChecklistId}", id);
    }

    #endregion

    #region Result Operations

    public async Task<StigChecklistResult?> GetResultByIdAsync(int id)
    {
        return await _context.StigChecklistResults
            .Include(r => r.Checklist)
                .ThenInclude(c => c.Host)
            .Include(r => r.Checklist)
                .ThenInclude(c => c.BenchmarkVersion)
                    .ThenInclude(v => v.StigBenchmark)
            .Include(r => r.StigRule)
            .FirstOrDefaultAsync(r => r.Id == id);
    }

    public async Task<IEnumerable<StigChecklistResult>> GetResultsForChecklistAsync(int checklistId, string? search = null, StigSeverity? severity = null, StigResultStatus? status = null)
    {
        var query = _context.StigChecklistResults
            .Include(r => r.StigRule)
            .Where(r => r.ChecklistId == checklistId);

        if (!string.IsNullOrWhiteSpace(search))
        {
            var term = search.ToLower();
            query = query.Where(r =>
                r.StigRule.VulnId.ToLower().Contains(term) ||
                r.StigRule.RuleId.ToLower().Contains(term) ||
                r.StigRule.RuleTitle.ToLower().Contains(term) ||
                (r.StigRule.RuleVersion != null && r.StigRule.RuleVersion.ToLower().Contains(term)));
        }

        if (severity.HasValue)
        {
            query = query.Where(r => r.StigRule.Severity == severity.Value);
        }

        if (status.HasValue)
        {
            query = query.Where(r => r.Status == status.Value);
        }

        return await query
            .OrderBy(r => r.StigRule.VulnId)
            .ToListAsync();
    }

    public async Task UpdateResultAsync(int resultId, StigResultStatus status, string? findingDetails, string? comments, int? userId)
    {
        var result = await _context.StigChecklistResults
            .Include(r => r.Checklist)
            .FirstOrDefaultAsync(r => r.Id == resultId)
            ?? throw new ArgumentException("Result not found");

        result.Status = status;
        result.FindingDetails = findingDetails;
        result.Comments = comments;
        result.ModifiedById = userId;
        result.LastModifiedDate = DateTime.UtcNow;

        result.Checklist.LastModifiedById = userId;
        result.Checklist.LastModifiedDate = DateTime.UtcNow;

        await _context.SaveChangesAsync();
        await UpdateChecklistStatsAsync(result.ChecklistId);
    }

    public async Task BulkUpdateResultsAsync(IEnumerable<int> resultIds, StigResultStatus status, int? userId)
    {
        var results = await _context.StigChecklistResults
            .Include(r => r.Checklist)
            .Where(r => resultIds.Contains(r.Id))
            .ToListAsync();

        var checklistIds = new HashSet<int>();

        foreach (var result in results)
        {
            result.Status = status;
            result.ModifiedById = userId;
            result.LastModifiedDate = DateTime.UtcNow;
            checklistIds.Add(result.ChecklistId);
        }

        await _context.SaveChangesAsync();

        foreach (var checklistId in checklistIds)
        {
            await UpdateChecklistStatsAsync(checklistId);
        }
    }

    public async Task UpdateChecklistStatsAsync(int checklistId)
    {
        var stats = await _context.StigChecklistResults
            .Where(r => r.ChecklistId == checklistId)
            .GroupBy(r => r.Status)
            .Select(g => new { Status = g.Key, Count = g.Count() })
            .ToListAsync();

        var checklist = await _context.StigChecklists.FindAsync(checklistId);
        if (checklist == null) return;

        checklist.NotReviewedCount = stats.FirstOrDefault(s => s.Status == StigResultStatus.NotReviewed)?.Count ?? 0;
        checklist.OpenCount = stats.FirstOrDefault(s => s.Status == StigResultStatus.Open)?.Count ?? 0;
        checklist.NotAFindingCount = stats.FirstOrDefault(s => s.Status == StigResultStatus.NotAFinding)?.Count ?? 0;
        checklist.NotApplicableCount = stats.FirstOrDefault(s => s.Status == StigResultStatus.NotApplicable)?.Count ?? 0;

        // Update status based on completion
        var total = stats.Sum(s => s.Count);
        if (checklist.NotReviewedCount == total)
        {
            checklist.Status = ChecklistStatus.Draft;
        }
        else if (checklist.NotReviewedCount == 0)
        {
            checklist.Status = ChecklistStatus.Complete;
        }
        else
        {
            checklist.Status = ChecklistStatus.InProgress;
        }

        await _context.SaveChangesAsync();
    }

    #endregion

    #region Import Operations

    public async Task<ChecklistImportResult> ImportFromCklbAsync(Stream jsonStream, int hostId, string fileName, int? userId)
    {
        var result = new ChecklistImportResult { Success = true };

        try
        {
            using var reader = new StreamReader(jsonStream);
            var json = await reader.ReadToEndAsync();
            var cklb = JsonSerializer.Deserialize<CklbDocument>(json, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            });

            if (cklb?.Stigs == null || !cklb.Stigs.Any())
            {
                result.Success = false;
                result.ErrorMessage = "Invalid CKLB file: no STIGs found";
                return result;
            }

            // For now, process the first STIG in the file
            var stigData = cklb.Stigs.First();

            // Find matching benchmark version
            var benchmarkVersion = await FindOrCreateBenchmarkVersionAsync(stigData);
            if (benchmarkVersion == null)
            {
                result.Success = false;
                result.ErrorMessage = $"STIG '{stigData.StigName}' not found in library. Please import the STIG first.";
                return result;
            }

            // Check for existing checklist
            var existingChecklist = await _context.StigChecklists
                .Include(c => c.Results)
                .FirstOrDefaultAsync(c => c.HostId == hostId && c.BenchmarkVersionId == benchmarkVersion.Id);

            StigChecklist checklist;
            if (existingChecklist != null)
            {
                checklist = existingChecklist;
                result.IsNewChecklist = false;
            }
            else
            {
                checklist = await CreateChecklistAsync(hostId, benchmarkVersion.Id, cklb.Title, userId);
                result.IsNewChecklist = true;
            }

            checklist.ImportSource = fileName;
            checklist.LastModifiedById = userId;
            checklist.LastModifiedDate = DateTime.UtcNow;

            // Import rule results
            var ruleMap = await _context.StigRules
                .Where(r => r.BenchmarkVersionId == benchmarkVersion.Id)
                .ToDictionaryAsync(r => r.VulnId, r => r.Id);

            var resultMap = checklist.Results.ToDictionary(r => r.StigRuleId, r => r);

            foreach (var ruleData in stigData.Rules ?? Enumerable.Empty<CklbRule>())
            {
                if (string.IsNullOrEmpty(ruleData.GroupId)) continue;

                if (!ruleMap.TryGetValue(ruleData.GroupId, out var ruleId))
                {
                    result.Warnings.Add($"Rule {ruleData.GroupId} not found in benchmark");
                    continue;
                }

                if (!resultMap.TryGetValue(ruleId, out var checklistResult))
                {
                    checklistResult = new StigChecklistResult
                    {
                        ChecklistId = checklist.Id,
                        StigRuleId = ruleId
                    };
                    _context.StigChecklistResults.Add(checklistResult);
                    result.ResultsImported++;
                }
                else
                {
                    result.ResultsUpdated++;
                }

                checklistResult.Status = ParseCklbStatus(ruleData.Status);
                checklistResult.FindingDetails = ruleData.FindingDetails;
                checklistResult.Comments = ruleData.Comments;
                checklistResult.ModifiedById = userId;
                checklistResult.LastModifiedDate = DateTime.UtcNow;
            }

            await _context.SaveChangesAsync();
            await UpdateChecklistStatsAsync(checklist.Id);

            result.ChecklistId = checklist.Id;
            result.StigName = stigData.StigName;
            result.Version = stigData.Version;
            result.TotalRules = benchmarkVersion.RuleCount;
            result.OpenCount = checklist.OpenCount;
            result.NotAFindingCount = checklist.NotAFindingCount;
            result.NotApplicableCount = checklist.NotApplicableCount;
            result.NotReviewedCount = checklist.NotReviewedCount;

            _logger.LogInformation("Imported CKLB for host {HostId}: {ResultsImported} new, {ResultsUpdated} updated",
                hostId, result.ResultsImported, result.ResultsUpdated);
        }
        catch (JsonException ex)
        {
            result.Success = false;
            result.ErrorMessage = $"Invalid CKLB JSON format: {ex.Message}";
            _logger.LogError(ex, "Error parsing CKLB file {FileName}", fileName);
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.ErrorMessage = $"Error importing CKLB: {ex.Message}";
            _logger.LogError(ex, "Error importing CKLB file {FileName}", fileName);
        }

        return result;
    }

    public async Task<ChecklistImportResult> ImportFromXccdfResultsAsync(Stream xmlStream, int hostId, string fileName, int? userId)
    {
        var result = new ChecklistImportResult { Success = true };

        try
        {
            var doc = await XDocument.LoadAsync(xmlStream, LoadOptions.None, CancellationToken.None);
            XNamespace cdf = "http://checklists.nist.gov/xccdf/1.1";

            var benchmark = doc.Root;
            if (benchmark == null || benchmark.Name.LocalName != "Benchmark")
            {
                result.Success = false;
                result.ErrorMessage = "Invalid XCCDF file: root element is not Benchmark";
                return result;
            }

            // Get benchmark ID from the root element
            var benchmarkId = benchmark.Attribute("id")?.Value ?? "";

            // Find TestResult element with rule-result children
            var testResult = benchmark.Descendants(cdf + "TestResult").FirstOrDefault();
            if (testResult == null)
            {
                result.Success = false;
                result.ErrorMessage = "Invalid XCCDF file: no TestResult element found. This file may be a STIG definition, not scan results.";
                return result;
            }

            // Parse rule results - they contain rule IDs and pass/fail status
            var ruleResults = testResult.Elements(cdf + "rule-result")
                .Select(rr => new
                {
                    RuleId = rr.Attribute("idref")?.Value ?? "",
                    ResultStatus = rr.Element(cdf + "result")?.Value ?? ""
                })
                .Where(r => !string.IsNullOrEmpty(r.RuleId))
                .ToList();

            if (!ruleResults.Any())
            {
                result.Success = false;
                result.ErrorMessage = "No rule results found in XCCDF file";
                return result;
            }

            // Find matching benchmark version by looking up rules by their IDs
            // Try multiple rule IDs since the first one might not match
            StigBenchmarkVersion? benchmarkVersion = null;
            var ruleIdsToTry = ruleResults.Select(r => r.RuleId).Distinct().Take(10).ToList();

            foreach (var ruleIdToCheck in ruleIdsToTry)
            {
                var matchingRule = await _context.StigRules
                    .Include(r => r.BenchmarkVersion)
                        .ThenInclude(v => v.StigBenchmark)
                    .FirstOrDefaultAsync(r => r.RuleId == ruleIdToCheck);

                if (matchingRule != null)
                {
                    benchmarkVersion = matchingRule.BenchmarkVersion;
                    break;
                }
            }

            // If no rule match, try matching by benchmark ID (with partial matching for tailored profiles)
            if (benchmarkVersion == null)
            {
                // Try exact match first
                var bench = await _context.StigBenchmarks
                    .Include(b => b.CurrentVersion)
                    .FirstOrDefaultAsync(b => b.StigId == benchmarkId);

                if (bench == null)
                {
                    // Try partial match - the results file might be a tailored profile like "MS_Win_10_v1909up_NonDomain"
                    // while the library has "Microsoft_Windows_10_STIG" or similar
                    // Look for Windows 10 STIGs by searching for common keywords
                    var searchTerms = benchmarkId.Replace("_", " ").ToLower();
                    if (searchTerms.Contains("win") && (searchTerms.Contains("10") || searchTerms.Contains("11")))
                    {
                        bench = await _context.StigBenchmarks
                            .Include(b => b.CurrentVersion)
                            .FirstOrDefaultAsync(b => b.Title.ToLower().Contains("windows 10") ||
                                                      b.Title.ToLower().Contains("windows 11") ||
                                                      b.StigId.ToLower().Contains("windows_10") ||
                                                      b.StigId.ToLower().Contains("windows_11"));
                    }
                }

                benchmarkVersion = bench?.CurrentVersion;
            }

            if (benchmarkVersion == null)
            {
                // Provide more helpful error message with available STIGs
                var availableStigs = await _context.StigBenchmarks
                    .Select(b => b.Title)
                    .Take(5)
                    .ToListAsync();

                var stigList = availableStigs.Any()
                    ? $"\n\nAvailable STIGs in library:\n- {string.Join("\n- ", availableStigs)}"
                    : "\n\nNo STIGs found in library. Please import the Windows 10 STIG first.";

                result.Success = false;
                result.ErrorMessage = $"No matching STIG found in library for benchmark: {benchmarkId}{stigList}";
                return result;
            }

            // Check for existing checklist or create new
            var existingChecklist = await _context.StigChecklists
                .Include(c => c.Results)
                .FirstOrDefaultAsync(c => c.HostId == hostId && c.BenchmarkVersionId == benchmarkVersion.Id);

            StigChecklist checklist;
            if (existingChecklist != null)
            {
                checklist = existingChecklist;
                result.IsNewChecklist = false;
            }
            else
            {
                checklist = await CreateChecklistAsync(hostId, benchmarkVersion.Id, null, userId);
                result.IsNewChecklist = true;
            }

            checklist.ImportSource = fileName;
            checklist.LastModifiedById = userId;
            checklist.LastModifiedDate = DateTime.UtcNow;

            // Build multiple rule maps for different matching strategies
            var rules = await _context.StigRules
                .Where(r => r.BenchmarkVersionId == benchmarkVersion.Id)
                .ToListAsync();

            // Map 1: Exact RuleId match
            var ruleIdMap = rules.ToDictionary(r => r.RuleId, r => r.Id);

            // Map 2: VulnId match (V-XXXXXX format)
            var vulnIdMap = rules.ToDictionary(r => r.VulnId, r => r.Id);

            // Map 3: Base RuleId match (SV-XXXXXX without revision)
            var baseRuleIdMap = rules.ToDictionary(r => ExtractBaseRuleId(r.RuleId), r => r.Id);

            _logger.LogInformation("Benchmark version {VersionId} has {RuleCount} rules in database. Sample RuleId: {SampleRuleId}, VulnId: {SampleVulnId}",
                benchmarkVersion.Id, rules.Count,
                rules.FirstOrDefault()?.RuleId ?? "N/A",
                rules.FirstOrDefault()?.VulnId ?? "N/A");

            // Log what we're trying to match
            var firstResult = ruleResults.First();
            _logger.LogInformation("First XCCDF result: RuleId={RuleId}, BaseRuleId={BaseRuleId}, ExtractedVulnId={VulnId}",
                firstResult.RuleId,
                ExtractBaseRuleId(firstResult.RuleId),
                ExtractVulnIdFromRuleId(firstResult.RuleId));

            var resultMap = checklist.Results.ToDictionary(r => r.StigRuleId, r => r);
            var matchedCount = 0;
            var unmatchedRules = new List<string>();

            // Process each rule result
            foreach (var rr in ruleResults)
            {
                int ruleId;

                // Strategy 1: Exact RuleId match
                if (ruleIdMap.TryGetValue(rr.RuleId, out ruleId))
                {
                    // Found exact match
                }
                // Strategy 2: Base RuleId match (without revision suffix)
                else
                {
                    var baseRuleId = ExtractBaseRuleId(rr.RuleId);
                    if (baseRuleIdMap.TryGetValue(baseRuleId, out ruleId))
                    {
                        // Found by base rule ID
                    }
                    // Strategy 3: VulnId match
                    else
                    {
                        var vulnId = ExtractVulnIdFromRuleId(rr.RuleId);
                        if (vulnIdMap.TryGetValue(vulnId, out ruleId))
                        {
                            // Found by VulnId
                        }
                        else
                        {
                            // No match found
                            if (unmatchedRules.Count < 5)
                                unmatchedRules.Add($"{rr.RuleId} (vuln: {vulnId})");
                            continue;
                        }
                    }
                }

                matchedCount++;

                if (!resultMap.TryGetValue(ruleId, out var checklistResult))
                {
                    checklistResult = new StigChecklistResult
                    {
                        ChecklistId = checklist.Id,
                        StigRuleId = ruleId
                    };
                    _context.StigChecklistResults.Add(checklistResult);
                    resultMap[ruleId] = checklistResult;
                    result.ResultsImported++;
                }
                else
                {
                    result.ResultsUpdated++;
                }

                // Map XCCDF result status to our status
                checklistResult.Status = ParseXccdfResultStatus(rr.ResultStatus);
                checklistResult.ModifiedById = userId;
                checklistResult.LastModifiedDate = DateTime.UtcNow;
            }

            _logger.LogInformation("Matched {MatchedCount} of {TotalCount} rules. Unmatched samples: {Unmatched}",
                matchedCount, ruleResults.Count, string.Join(", ", unmatchedRules));

            await _context.SaveChangesAsync();
            await UpdateChecklistStatsAsync(checklist.Id);

            // Reload checklist to get updated counts
            checklist = (await GetChecklistByIdAsync(checklist.Id))!;

            result.ChecklistId = checklist.Id;
            result.StigName = benchmarkVersion.StigBenchmark.Title;
            result.Version = benchmarkVersion.Version;
            result.TotalRules = benchmarkVersion.RuleCount;
            result.OpenCount = checklist.OpenCount;
            result.NotAFindingCount = checklist.NotAFindingCount;
            result.NotApplicableCount = checklist.NotApplicableCount;
            result.NotReviewedCount = checklist.NotReviewedCount;

            _logger.LogInformation("Imported XCCDF results for host {HostId}: {ResultsImported} new, {ResultsUpdated} updated",
                hostId, result.ResultsImported, result.ResultsUpdated);
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.ErrorMessage = $"Error importing XCCDF results: {ex.Message}";
            _logger.LogError(ex, "Error importing XCCDF results file {FileName}", fileName);
        }

        return result;
    }

    private static StigResultStatus ParseXccdfResultStatus(string status)
    {
        // XCCDF result values: pass, fail, error, unknown, notapplicable, notchecked, notselected, informational, fixed
        return status.ToLower() switch
        {
            "pass" => StigResultStatus.NotAFinding,
            "fail" => StigResultStatus.Open,
            "notapplicable" => StigResultStatus.NotApplicable,
            "error" => StigResultStatus.Open, // Treat errors as findings
            "fixed" => StigResultStatus.NotAFinding, // Fixed means it was remediated
            _ => StigResultStatus.NotReviewed
        };
    }

    private async Task<StigBenchmarkVersion?> FindOrCreateBenchmarkVersionAsync(CklbStig stigData)
    {
        // Try to find by STIG ID and version
        var version = await _context.StigBenchmarkVersions
            .Include(v => v.StigBenchmark)
            .FirstOrDefaultAsync(v =>
                v.StigBenchmark.StigId == stigData.StigId &&
                v.Version == stigData.Version);

        if (version != null) return version;

        // Try to find current version of the benchmark
        var benchmark = await _context.StigBenchmarks
            .Include(b => b.CurrentVersion)
            .FirstOrDefaultAsync(b => b.StigId == stigData.StigId);

        return benchmark?.CurrentVersion;
    }

    private static StigResultStatus ParseCklbStatus(string? status)
    {
        return status?.ToLower() switch
        {
            "open" => StigResultStatus.Open,
            "not_a_finding" => StigResultStatus.NotAFinding,
            "notafinding" => StigResultStatus.NotAFinding,
            "not_applicable" => StigResultStatus.NotApplicable,
            "notapplicable" => StigResultStatus.NotApplicable,
            _ => StigResultStatus.NotReviewed
        };
    }

    #endregion

    #region Export Operations

    public async Task<byte[]> ExportToCklbAsync(int checklistId)
    {
        var checklist = await GetChecklistByIdAsync(checklistId)
            ?? throw new ArgumentException("Checklist not found");

        var cklb = new CklbDocument
        {
            Title = checklist.Title ?? "Exported Checklist",
            Id = Guid.NewGuid().ToString(),
            Stigs = new List<CklbStig>
            {
                new()
                {
                    StigName = checklist.BenchmarkVersion.StigBenchmark.Title,
                    DisplayName = checklist.BenchmarkVersion.StigBenchmark.Title,
                    StigId = checklist.BenchmarkVersion.StigBenchmark.StigId,
                    ReleaseInfo = checklist.BenchmarkVersion.ReleaseInfo,
                    Version = checklist.BenchmarkVersion.Version,
                    Uuid = Guid.NewGuid().ToString(),
                    Size = checklist.Results.Count,
                    Rules = checklist.Results.Select(r => new CklbRule
                    {
                        GroupIdSrc = r.StigRule.VulnId,
                        GroupId = r.StigRule.VulnId,
                        RuleIdSrc = r.StigRule.RuleId,
                        RuleId = r.StigRule.RuleId.Replace("_rule", ""),
                        RuleVersion = r.StigRule.RuleVersion,
                        RuleTitle = r.StigRule.RuleTitle,
                        Severity = r.StigRule.Severity.ToString().ToLower(),
                        Status = ConvertStatusToCklb(r.Status),
                        FindingDetails = r.FindingDetails ?? "",
                        Comments = r.Comments ?? "",
                        CheckContent = r.StigRule.CheckContent,
                        FixText = r.StigRule.FixText,
                        Discussion = r.StigRule.Discussion,
                        Ccis = r.StigRule.CCIs?.Split(',').ToList() ?? new List<string>()
                    }).ToList()
                }
            }
        };

        var json = JsonSerializer.Serialize(cklb, new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
            WriteIndented = true
        });

        return System.Text.Encoding.UTF8.GetBytes(json);
    }

    private static string ConvertStatusToCklb(StigResultStatus status)
    {
        return status switch
        {
            StigResultStatus.Open => "open",
            StigResultStatus.NotAFinding => "not_a_finding",
            StigResultStatus.NotApplicable => "not_applicable",
            _ => "not_reviewed"
        };
    }

    /// <summary>
    /// Extracts the base rule ID (SV-XXXXXX) from a full rule ID like "SV-220968r569187_rule"
    /// </summary>
    private static string ExtractBaseRuleId(string ruleId)
    {
        if (string.IsNullOrEmpty(ruleId)) return ruleId;

        // Rule IDs can be in formats like:
        // - SV-220968r569187_rule
        // - SV-220968_rule
        // - SV-220968
        // We want to extract just "SV-220968"

        // First, remove the "_rule" suffix if present
        var id = ruleId.Replace("_rule", "");

        // Then remove the revision suffix (rXXXXXX) if present
        var rIndex = id.IndexOf('r', 3); // Start after "SV-" to avoid matching the 'S'
        if (rIndex > 0)
        {
            id = id.Substring(0, rIndex);
        }

        return id;
    }

    /// <summary>
    /// Extracts the VulnId (V-XXXXXX) from a rule ID like "SV-220968r569187_rule"
    /// </summary>
    private static string ExtractVulnIdFromRuleId(string ruleId)
    {
        var baseId = ExtractBaseRuleId(ruleId);
        // Convert SV-XXXXXX to V-XXXXXX
        if (baseId.StartsWith("SV-", StringComparison.OrdinalIgnoreCase))
        {
            return "V-" + baseId.Substring(3);
        }
        return baseId;
    }

    #endregion

    #region CKLB DTOs

    private class CklbDocument
    {
        public string Title { get; set; } = "";
        public string Id { get; set; } = "";
        public List<CklbStig> Stigs { get; set; } = new();
    }

    private class CklbStig
    {
        public string StigName { get; set; } = "";
        public string DisplayName { get; set; } = "";
        public string StigId { get; set; } = "";
        public string ReleaseInfo { get; set; } = "";
        public string Version { get; set; } = "";
        public string Uuid { get; set; } = "";
        public int Size { get; set; }
        public List<CklbRule> Rules { get; set; } = new();
    }

    private class CklbRule
    {
        public string GroupIdSrc { get; set; } = "";
        public string GroupId { get; set; } = "";
        public string RuleIdSrc { get; set; } = "";
        public string RuleId { get; set; } = "";
        public string RuleVersion { get; set; } = "";
        public string RuleTitle { get; set; } = "";
        public string Severity { get; set; } = "";
        public string Status { get; set; } = "";
        public string FindingDetails { get; set; } = "";
        public string Comments { get; set; } = "";
        public string? CheckContent { get; set; }
        public string? FixText { get; set; }
        public string? Discussion { get; set; }
        public List<string> Ccis { get; set; } = new();
    }

    #endregion
}
