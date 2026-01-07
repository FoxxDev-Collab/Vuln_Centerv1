using VulnMgmt.Web.Models.Domain;

namespace VulnMgmt.Web.Services;

public interface IStigChecklistService
{
    // Checklist operations
    Task<IEnumerable<StigChecklist>> GetAllChecklistsAsync();
    Task<IEnumerable<StigChecklist>> GetChecklistsForHostAsync(int hostId);
    Task<StigChecklist?> GetChecklistByIdAsync(int id);
    Task<StigChecklist> CreateChecklistAsync(int hostId, int benchmarkVersionId, string? title, int? userId);
    Task DeleteChecklistAsync(int id);

    // Result operations
    Task<StigChecklistResult?> GetResultByIdAsync(int id);
    Task<IEnumerable<StigChecklistResult>> GetResultsForChecklistAsync(int checklistId, string? search = null, StigSeverity? severity = null, StigResultStatus? status = null);
    Task UpdateResultAsync(int resultId, StigResultStatus status, string? findingDetails, string? comments, int? userId);
    Task BulkUpdateResultsAsync(IEnumerable<int> resultIds, StigResultStatus status, int? userId);

    // Import operations
    Task<ChecklistImportResult> ImportFromCklbAsync(Stream jsonStream, int hostId, string fileName, int? userId);
    Task<ChecklistImportResult> ImportFromXccdfResultsAsync(Stream xmlStream, int hostId, string fileName, int? userId);

    // Export operations
    Task<byte[]> ExportToCklbAsync(int checklistId);

    // Statistics
    Task UpdateChecklistStatsAsync(int checklistId);
}

public class ChecklistImportResult
{
    public bool Success { get; set; }
    public string? ErrorMessage { get; set; }
    public List<string> Warnings { get; set; } = new();

    public int ChecklistId { get; set; }
    public string? StigName { get; set; }
    public string? Version { get; set; }
    public int TotalRules { get; set; }
    public int ResultsImported { get; set; }
    public int ResultsUpdated { get; set; }

    public int OpenCount { get; set; }
    public int NotAFindingCount { get; set; }
    public int NotApplicableCount { get; set; }
    public int NotReviewedCount { get; set; }

    public bool IsNewChecklist { get; set; }
}
