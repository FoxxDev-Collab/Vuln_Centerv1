using VulnMgmt.Web.Models.Domain;

namespace VulnMgmt.Web.Services;

public interface IStigLibraryService
{
    // Benchmark operations
    Task<IEnumerable<StigBenchmark>> GetAllBenchmarksAsync();
    Task<StigBenchmark?> GetBenchmarkByIdAsync(int id);
    Task<StigBenchmark?> GetBenchmarkByStigIdAsync(string stigId);
    Task<StigBenchmarkVersion?> GetBenchmarkVersionByIdAsync(int id);
    Task<IEnumerable<StigBenchmarkVersion>> GetVersionsForBenchmarkAsync(int benchmarkId);
    Task<StigRule?> GetRuleByIdAsync(int id);
    Task<IEnumerable<StigRule>> GetRulesForVersionAsync(int versionId, string? searchTerm = null, StigSeverity? severity = null);

    // Import operations
    Task<StigImportResult> ImportFromXccdfAsync(Stream xmlStream, string fileName);
    Task<StigImportResult> ImportFromZipAsync(Stream zipStream, string fileName);

    // Version management
    Task SetCurrentVersionAsync(int benchmarkId, int versionId);
    Task DeleteVersionAsync(int versionId);
    Task DeleteBenchmarkAsync(int benchmarkId);

    // Statistics
    Task<StigLibraryStats> GetLibraryStatsAsync();
}

public class StigImportResult
{
    public bool Success { get; set; }
    public string? ErrorMessage { get; set; }
    public List<string> Errors { get; set; } = new();
    public List<string> Warnings { get; set; } = new();

    public int BenchmarksImported { get; set; }
    public int VersionsCreated { get; set; }
    public int RulesImported { get; set; }
    public int FilesProcessed { get; set; }

    public List<ImportedBenchmarkInfo> ImportedBenchmarks { get; set; } = new();
}

public class ImportedBenchmarkInfo
{
    public int BenchmarkId { get; set; }
    public int VersionId { get; set; }
    public string StigId { get; set; } = string.Empty;
    public string Title { get; set; } = string.Empty;
    public string Version { get; set; } = string.Empty;
    public string? Release { get; set; }
    public int RuleCount { get; set; }
    public bool IsNewBenchmark { get; set; }
    public bool IsNewVersion { get; set; }
}

public class StigLibraryStats
{
    public int TotalBenchmarks { get; set; }
    public int TotalVersions { get; set; }
    public int TotalRules { get; set; }
    public int TotalChecklists { get; set; }
    public Dictionary<StigSeverity, int> RulesBySeverity { get; set; } = new();
}
