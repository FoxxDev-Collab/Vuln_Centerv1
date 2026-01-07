using Microsoft.EntityFrameworkCore;
using VulnMgmt.Web.Models.Domain;

namespace VulnMgmt.Web.Data;

public class ApplicationDbContext : DbContext
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options)
    {
    }

    public DbSet<Site> Sites => Set<Site>();
    public DbSet<Models.Domain.Host> Hosts => Set<Models.Domain.Host>();
    public DbSet<HostVulnerability> HostVulnerabilities => Set<HostVulnerability>();
    public DbSet<ScanImport> ScanImports => Set<ScanImport>();
    public DbSet<User> Users => Set<User>();
    public DbSet<AuditLog> AuditLogs => Set<AuditLog>();

    // STIG Library entities
    public DbSet<StigBenchmark> StigBenchmarks => Set<StigBenchmark>();
    public DbSet<StigBenchmarkVersion> StigBenchmarkVersions => Set<StigBenchmarkVersion>();
    public DbSet<StigRule> StigRules => Set<StigRule>();
    public DbSet<StigChecklist> StigChecklists => Set<StigChecklist>();
    public DbSet<StigChecklistResult> StigChecklistResults => Set<StigChecklistResult>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        // Site configuration
        modelBuilder.Entity<Site>(entity =>
        {
            entity.HasIndex(e => e.Name);
            entity.HasIndex(e => e.OrganizationName);
        });

        // Host configuration
        modelBuilder.Entity<Models.Domain.Host>(entity =>
        {
            entity.HasIndex(e => e.DNSName);
            entity.HasIndex(e => e.NetBIOSName);
            entity.HasIndex(e => e.SiteId);

            entity.HasOne(h => h.Site)
                .WithMany(s => s.Hosts)
                .HasForeignKey(h => h.SiteId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        // HostVulnerability configuration
        modelBuilder.Entity<HostVulnerability>(entity =>
        {
            entity.HasIndex(e => e.HostId);
            entity.HasIndex(e => e.PluginId);
            entity.HasIndex(e => e.Severity);
            entity.HasIndex(e => e.RemediationStatus);
            entity.HasIndex(e => new { e.HostId, e.PluginId });

            entity.HasOne(v => v.Host)
                .WithMany(h => h.Vulnerabilities)
                .HasForeignKey(v => v.HostId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        // ScanImport configuration
        modelBuilder.Entity<ScanImport>(entity =>
        {
            entity.HasIndex(e => e.SiteId);
            entity.HasIndex(e => e.ImportDate);

            entity.HasOne(s => s.Site)
                .WithMany(site => site.ScanImports)
                .HasForeignKey(s => s.SiteId)
                .OnDelete(DeleteBehavior.Cascade);

            entity.HasOne(s => s.ImportedBy)
                .WithMany(u => u.ScanImports)
                .HasForeignKey(s => s.ImportedById)
                .OnDelete(DeleteBehavior.SetNull);
        });

        // User configuration
        modelBuilder.Entity<User>(entity =>
        {
            entity.HasIndex(e => e.Username).IsUnique();
            entity.HasIndex(e => e.Email);
        });

        // AuditLog configuration
        modelBuilder.Entity<AuditLog>(entity =>
        {
            entity.HasIndex(e => e.UserId);
            entity.HasIndex(e => e.Timestamp);
            entity.HasIndex(e => new { e.EntityType, e.EntityId });

            entity.HasOne(a => a.User)
                .WithMany(u => u.AuditLogs)
                .HasForeignKey(a => a.UserId)
                .OnDelete(DeleteBehavior.SetNull);
        });

        // StigBenchmark configuration
        modelBuilder.Entity<StigBenchmark>(entity =>
        {
            entity.HasIndex(e => e.StigId).IsUnique();
            entity.HasIndex(e => e.Title);

            entity.HasOne(b => b.CurrentVersion)
                .WithMany()
                .HasForeignKey(b => b.CurrentVersionId)
                .OnDelete(DeleteBehavior.SetNull);
        });

        // StigBenchmarkVersion configuration
        modelBuilder.Entity<StigBenchmarkVersion>(entity =>
        {
            entity.HasIndex(e => e.StigBenchmarkId);
            entity.HasIndex(e => new { e.StigBenchmarkId, e.Version, e.Release }).IsUnique();

            entity.HasOne(v => v.StigBenchmark)
                .WithMany(b => b.Versions)
                .HasForeignKey(v => v.StigBenchmarkId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        // StigRule configuration
        modelBuilder.Entity<StigRule>(entity =>
        {
            entity.HasIndex(e => e.BenchmarkVersionId);
            entity.HasIndex(e => e.VulnId);
            entity.HasIndex(e => e.RuleId);
            entity.HasIndex(e => e.Severity);
            entity.HasIndex(e => new { e.BenchmarkVersionId, e.VulnId }).IsUnique();

            entity.HasOne(r => r.BenchmarkVersion)
                .WithMany(v => v.Rules)
                .HasForeignKey(r => r.BenchmarkVersionId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        // StigChecklist configuration
        modelBuilder.Entity<StigChecklist>(entity =>
        {
            entity.HasIndex(e => e.HostId);
            entity.HasIndex(e => e.BenchmarkVersionId);
            entity.HasIndex(e => e.Status);

            entity.HasOne(c => c.Host)
                .WithMany()
                .HasForeignKey(c => c.HostId)
                .OnDelete(DeleteBehavior.Cascade);

            entity.HasOne(c => c.BenchmarkVersion)
                .WithMany(v => v.Checklists)
                .HasForeignKey(c => c.BenchmarkVersionId)
                .OnDelete(DeleteBehavior.Restrict);

            entity.HasOne(c => c.CreatedBy)
                .WithMany()
                .HasForeignKey(c => c.CreatedById)
                .OnDelete(DeleteBehavior.SetNull);

            entity.HasOne(c => c.LastModifiedBy)
                .WithMany()
                .HasForeignKey(c => c.LastModifiedById)
                .OnDelete(DeleteBehavior.SetNull);
        });

        // StigChecklistResult configuration
        modelBuilder.Entity<StigChecklistResult>(entity =>
        {
            entity.HasIndex(e => e.ChecklistId);
            entity.HasIndex(e => e.StigRuleId);
            entity.HasIndex(e => e.Status);
            entity.HasIndex(e => new { e.ChecklistId, e.StigRuleId }).IsUnique();

            entity.HasOne(r => r.Checklist)
                .WithMany(c => c.Results)
                .HasForeignKey(r => r.ChecklistId)
                .OnDelete(DeleteBehavior.Cascade);

            entity.HasOne(r => r.StigRule)
                .WithMany(rule => rule.ChecklistResults)
                .HasForeignKey(r => r.StigRuleId)
                .OnDelete(DeleteBehavior.Restrict);

            entity.HasOne(r => r.ModifiedBy)
                .WithMany()
                .HasForeignKey(r => r.ModifiedById)
                .OnDelete(DeleteBehavior.SetNull);
        });
    }
}
