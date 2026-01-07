using VulnMgmt.Web.Models.ViewModels;

namespace VulnMgmt.Web.Services;

public interface INistComplianceExportService
{
    /// <summary>
    /// Gets a preview of what will be exported for the given site
    /// </summary>
    Task<NistExportPreview?> GetExportPreviewAsync(int siteId);

    /// <summary>
    /// Gets all sites with host counts for the export form
    /// </summary>
    Task<List<SiteSelectItem>> GetSitesForExportAsync();

    /// <summary>
    /// Exports all STIG and Nessus data for a site to a comprehensive JSON format
    /// </summary>
    Task<byte[]> ExportSiteToJsonAsync(int siteId, int? userId);

    /// <summary>
    /// Gets a preview of what will be exported for all sites combined
    /// </summary>
    Task<NistExportAllPreview> GetExportAllPreviewAsync();

    /// <summary>
    /// Exports all STIG and Nessus data for ALL sites to a comprehensive JSON format
    /// </summary>
    Task<byte[]> ExportAllSitesToJsonAsync(int? userId);
}
