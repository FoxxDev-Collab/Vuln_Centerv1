using VulnMgmt.Web.Models.Domain;
using VulnMgmt.Web.Models.ViewModels;

namespace VulnMgmt.Web.Services;

public interface IScanImportService
{
    /// <summary>
    /// Import vulnerabilities from a Nessus CSV file
    /// </summary>
    Task<ScanImportResultViewModel> ImportNessusCsvAsync(
        Stream fileStream,
        string fileName,
        int siteId,
        int? importedById,
        bool updateExisting = true,
        string? notes = null);

    /// <summary>
    /// Get all scan imports with optional site filter
    /// </summary>
    Task<IEnumerable<ScanImportListItem>> GetAllImportsAsync(int? siteId = null);

    /// <summary>
    /// Get a specific scan import by ID
    /// </summary>
    Task<ScanImport?> GetImportByIdAsync(int id);

    /// <summary>
    /// Delete a scan import record (does not delete imported vulnerabilities)
    /// </summary>
    Task DeleteImportAsync(int id);
}
