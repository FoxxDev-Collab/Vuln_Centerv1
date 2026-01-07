using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace VulnMgmt.Web.Migrations
{
    /// <inheritdoc />
    public partial class InitialCreate : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "Sites",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    Name = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    Description = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    Location = table.Column<string>(type: "TEXT", maxLength: 200, nullable: true),
                    OrganizationName = table.Column<string>(type: "TEXT", maxLength: 200, nullable: true),
                    POCName = table.Column<string>(type: "TEXT", maxLength: 100, nullable: true),
                    POCEmail = table.Column<string>(type: "TEXT", maxLength: 100, nullable: true),
                    POCPhone = table.Column<string>(type: "TEXT", maxLength: 20, nullable: true),
                    IsActive = table.Column<bool>(type: "INTEGER", nullable: false),
                    CreatedDate = table.Column<DateTime>(type: "TEXT", nullable: false),
                    ModifiedDate = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Sites", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Users",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    Username = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    Email = table.Column<string>(type: "TEXT", maxLength: 200, nullable: true),
                    DisplayName = table.Column<string>(type: "TEXT", maxLength: 100, nullable: true),
                    Phone = table.Column<string>(type: "TEXT", maxLength: 20, nullable: true),
                    PasswordHash = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    Role = table.Column<int>(type: "INTEGER", nullable: false),
                    IsWindowsAuth = table.Column<bool>(type: "INTEGER", nullable: false),
                    IsActive = table.Column<bool>(type: "INTEGER", nullable: false),
                    CreatedDate = table.Column<DateTime>(type: "TEXT", nullable: false),
                    ModifiedDate = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Users", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Hosts",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    SiteId = table.Column<int>(type: "INTEGER", nullable: false),
                    DNSName = table.Column<string>(type: "TEXT", maxLength: 255, nullable: true),
                    NetBIOSName = table.Column<string>(type: "TEXT", maxLength: 15, nullable: true),
                    DisplayName = table.Column<string>(type: "TEXT", maxLength: 100, nullable: true),
                    Description = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    OperatingSystem = table.Column<string>(type: "TEXT", maxLength: 200, nullable: true),
                    OSVersion = table.Column<string>(type: "TEXT", maxLength: 100, nullable: true),
                    LastKnownIPAddress = table.Column<string>(type: "TEXT", maxLength: 45, nullable: true),
                    LastKnownMACAddress = table.Column<string>(type: "TEXT", maxLength: 17, nullable: true),
                    AssetType = table.Column<int>(type: "INTEGER", nullable: false),
                    AssetTag = table.Column<string>(type: "TEXT", maxLength: 50, nullable: true),
                    SerialNumber = table.Column<string>(type: "TEXT", maxLength: 50, nullable: true),
                    Status = table.Column<int>(type: "INTEGER", nullable: false),
                    LastScanDate = table.Column<DateTime>(type: "TEXT", nullable: true),
                    LastScanVulnCount = table.Column<int>(type: "INTEGER", nullable: false),
                    CreatedDate = table.Column<DateTime>(type: "TEXT", nullable: false),
                    ModifiedDate = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Hosts", x => x.Id);
                    table.ForeignKey(
                        name: "FK_Hosts_Sites_SiteId",
                        column: x => x.SiteId,
                        principalTable: "Sites",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "AuditLogs",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    UserId = table.Column<int>(type: "INTEGER", nullable: true),
                    Action = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    EntityType = table.Column<string>(type: "TEXT", maxLength: 100, nullable: true),
                    EntityId = table.Column<int>(type: "INTEGER", nullable: true),
                    OldValues = table.Column<string>(type: "TEXT", nullable: true),
                    NewValues = table.Column<string>(type: "TEXT", nullable: true),
                    Timestamp = table.Column<DateTime>(type: "TEXT", nullable: false),
                    IpAddress = table.Column<string>(type: "TEXT", maxLength: 45, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AuditLogs", x => x.Id);
                    table.ForeignKey(
                        name: "FK_AuditLogs_Users_UserId",
                        column: x => x.UserId,
                        principalTable: "Users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                });

            migrationBuilder.CreateTable(
                name: "ScanImports",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    SiteId = table.Column<int>(type: "INTEGER", nullable: false),
                    FileName = table.Column<string>(type: "TEXT", maxLength: 500, nullable: false),
                    ImportDate = table.Column<DateTime>(type: "TEXT", nullable: false),
                    TotalRows = table.Column<int>(type: "INTEGER", nullable: false),
                    HostsCreated = table.Column<int>(type: "INTEGER", nullable: false),
                    HostsUpdated = table.Column<int>(type: "INTEGER", nullable: false),
                    VulnerabilitiesImported = table.Column<int>(type: "INTEGER", nullable: false),
                    VulnerabilitiesUpdated = table.Column<int>(type: "INTEGER", nullable: false),
                    ImportedById = table.Column<int>(type: "INTEGER", nullable: true),
                    Notes = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ScanImports", x => x.Id);
                    table.ForeignKey(
                        name: "FK_ScanImports_Sites_SiteId",
                        column: x => x.SiteId,
                        principalTable: "Sites",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_ScanImports_Users_ImportedById",
                        column: x => x.ImportedById,
                        principalTable: "Users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                });

            migrationBuilder.CreateTable(
                name: "HostVulnerabilities",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    HostId = table.Column<int>(type: "INTEGER", nullable: false),
                    PluginId = table.Column<int>(type: "INTEGER", nullable: false),
                    PluginName = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    Family = table.Column<string>(type: "TEXT", maxLength: 200, nullable: true),
                    Severity = table.Column<int>(type: "INTEGER", nullable: false),
                    IPAddress = table.Column<string>(type: "TEXT", maxLength: 45, nullable: true),
                    Protocol = table.Column<string>(type: "TEXT", maxLength: 20, nullable: true),
                    Port = table.Column<int>(type: "INTEGER", nullable: true),
                    MACAddress = table.Column<string>(type: "TEXT", maxLength: 17, nullable: true),
                    IsExploitable = table.Column<bool>(type: "INTEGER", nullable: false),
                    ExploitFrameworks = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    ExploitEase = table.Column<string>(type: "TEXT", maxLength: 100, nullable: true),
                    CVE = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    VulnPublicationDate = table.Column<DateTime>(type: "TEXT", nullable: true),
                    Synopsis = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: true),
                    Description = table.Column<string>(type: "TEXT", nullable: true),
                    Solution = table.Column<string>(type: "TEXT", nullable: true),
                    SeeAlso = table.Column<string>(type: "TEXT", nullable: true),
                    PluginText = table.Column<string>(type: "TEXT", nullable: true),
                    Repository = table.Column<string>(type: "TEXT", maxLength: 200, nullable: true),
                    FirstDiscovered = table.Column<DateTime>(type: "TEXT", nullable: true),
                    LastObserved = table.Column<DateTime>(type: "TEXT", nullable: true),
                    RemediationStatus = table.Column<int>(type: "INTEGER", nullable: false),
                    RemediationNotes = table.Column<string>(type: "TEXT", nullable: true),
                    RemediationDate = table.Column<DateTime>(type: "TEXT", nullable: true),
                    ImportedDate = table.Column<DateTime>(type: "TEXT", nullable: false),
                    ImportSource = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    CreatedDate = table.Column<DateTime>(type: "TEXT", nullable: false),
                    ModifiedDate = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_HostVulnerabilities", x => x.Id);
                    table.ForeignKey(
                        name: "FK_HostVulnerabilities_Hosts_HostId",
                        column: x => x.HostId,
                        principalTable: "Hosts",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_AuditLogs_EntityType_EntityId",
                table: "AuditLogs",
                columns: new[] { "EntityType", "EntityId" });

            migrationBuilder.CreateIndex(
                name: "IX_AuditLogs_Timestamp",
                table: "AuditLogs",
                column: "Timestamp");

            migrationBuilder.CreateIndex(
                name: "IX_AuditLogs_UserId",
                table: "AuditLogs",
                column: "UserId");

            migrationBuilder.CreateIndex(
                name: "IX_Hosts_DNSName",
                table: "Hosts",
                column: "DNSName");

            migrationBuilder.CreateIndex(
                name: "IX_Hosts_NetBIOSName",
                table: "Hosts",
                column: "NetBIOSName");

            migrationBuilder.CreateIndex(
                name: "IX_Hosts_SiteId",
                table: "Hosts",
                column: "SiteId");

            migrationBuilder.CreateIndex(
                name: "IX_HostVulnerabilities_HostId",
                table: "HostVulnerabilities",
                column: "HostId");

            migrationBuilder.CreateIndex(
                name: "IX_HostVulnerabilities_HostId_PluginId",
                table: "HostVulnerabilities",
                columns: new[] { "HostId", "PluginId" });

            migrationBuilder.CreateIndex(
                name: "IX_HostVulnerabilities_PluginId",
                table: "HostVulnerabilities",
                column: "PluginId");

            migrationBuilder.CreateIndex(
                name: "IX_HostVulnerabilities_RemediationStatus",
                table: "HostVulnerabilities",
                column: "RemediationStatus");

            migrationBuilder.CreateIndex(
                name: "IX_HostVulnerabilities_Severity",
                table: "HostVulnerabilities",
                column: "Severity");

            migrationBuilder.CreateIndex(
                name: "IX_ScanImports_ImportDate",
                table: "ScanImports",
                column: "ImportDate");

            migrationBuilder.CreateIndex(
                name: "IX_ScanImports_ImportedById",
                table: "ScanImports",
                column: "ImportedById");

            migrationBuilder.CreateIndex(
                name: "IX_ScanImports_SiteId",
                table: "ScanImports",
                column: "SiteId");

            migrationBuilder.CreateIndex(
                name: "IX_Sites_Name",
                table: "Sites",
                column: "Name");

            migrationBuilder.CreateIndex(
                name: "IX_Sites_OrganizationName",
                table: "Sites",
                column: "OrganizationName");

            migrationBuilder.CreateIndex(
                name: "IX_Users_Email",
                table: "Users",
                column: "Email");

            migrationBuilder.CreateIndex(
                name: "IX_Users_Username",
                table: "Users",
                column: "Username",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "AuditLogs");

            migrationBuilder.DropTable(
                name: "HostVulnerabilities");

            migrationBuilder.DropTable(
                name: "ScanImports");

            migrationBuilder.DropTable(
                name: "Hosts");

            migrationBuilder.DropTable(
                name: "Users");

            migrationBuilder.DropTable(
                name: "Sites");
        }
    }
}
