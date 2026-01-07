using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace VulnMgmt.Web.Migrations
{
    /// <inheritdoc />
    public partial class AddStigLibrary : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "StigBenchmarks",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    StigId = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    Title = table.Column<string>(type: "TEXT", maxLength: 500, nullable: false),
                    Description = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: true),
                    CurrentVersionId = table.Column<int>(type: "INTEGER", nullable: true),
                    CreatedDate = table.Column<DateTime>(type: "TEXT", nullable: false),
                    ModifiedDate = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_StigBenchmarks", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "StigBenchmarkVersions",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    StigBenchmarkId = table.Column<int>(type: "INTEGER", nullable: false),
                    Version = table.Column<string>(type: "TEXT", maxLength: 50, nullable: false),
                    Release = table.Column<string>(type: "TEXT", maxLength: 50, nullable: true),
                    ReleaseInfo = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    BenchmarkDate = table.Column<DateTime>(type: "TEXT", nullable: true),
                    FileName = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    ImportDate = table.Column<DateTime>(type: "TEXT", nullable: false),
                    RuleCount = table.Column<int>(type: "INTEGER", nullable: false),
                    IsActive = table.Column<bool>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_StigBenchmarkVersions", x => x.Id);
                    table.ForeignKey(
                        name: "FK_StigBenchmarkVersions_StigBenchmarks_StigBenchmarkId",
                        column: x => x.StigBenchmarkId,
                        principalTable: "StigBenchmarks",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "StigChecklists",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    HostId = table.Column<int>(type: "INTEGER", nullable: false),
                    BenchmarkVersionId = table.Column<int>(type: "INTEGER", nullable: false),
                    Title = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    Status = table.Column<int>(type: "INTEGER", nullable: false),
                    CreatedById = table.Column<int>(type: "INTEGER", nullable: true),
                    LastModifiedById = table.Column<int>(type: "INTEGER", nullable: true),
                    ImportSource = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    CreatedDate = table.Column<DateTime>(type: "TEXT", nullable: false),
                    LastModifiedDate = table.Column<DateTime>(type: "TEXT", nullable: false),
                    NotReviewedCount = table.Column<int>(type: "INTEGER", nullable: false),
                    OpenCount = table.Column<int>(type: "INTEGER", nullable: false),
                    NotAFindingCount = table.Column<int>(type: "INTEGER", nullable: false),
                    NotApplicableCount = table.Column<int>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_StigChecklists", x => x.Id);
                    table.ForeignKey(
                        name: "FK_StigChecklists_Hosts_HostId",
                        column: x => x.HostId,
                        principalTable: "Hosts",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_StigChecklists_StigBenchmarkVersions_BenchmarkVersionId",
                        column: x => x.BenchmarkVersionId,
                        principalTable: "StigBenchmarkVersions",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_StigChecklists_Users_CreatedById",
                        column: x => x.CreatedById,
                        principalTable: "Users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                    table.ForeignKey(
                        name: "FK_StigChecklists_Users_LastModifiedById",
                        column: x => x.LastModifiedById,
                        principalTable: "Users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                });

            migrationBuilder.CreateTable(
                name: "StigRules",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    BenchmarkVersionId = table.Column<int>(type: "INTEGER", nullable: false),
                    VulnId = table.Column<string>(type: "TEXT", maxLength: 50, nullable: false),
                    RuleId = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    GroupId = table.Column<string>(type: "TEXT", maxLength: 50, nullable: true),
                    GroupTitle = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    Severity = table.Column<int>(type: "INTEGER", nullable: false),
                    RuleVersion = table.Column<string>(type: "TEXT", maxLength: 100, nullable: true),
                    RuleTitle = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: false),
                    Discussion = table.Column<string>(type: "TEXT", nullable: true),
                    CheckContent = table.Column<string>(type: "TEXT", nullable: true),
                    FixText = table.Column<string>(type: "TEXT", nullable: true),
                    CCIs = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: true),
                    LegacyIds = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    Weight = table.Column<decimal>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_StigRules", x => x.Id);
                    table.ForeignKey(
                        name: "FK_StigRules_StigBenchmarkVersions_BenchmarkVersionId",
                        column: x => x.BenchmarkVersionId,
                        principalTable: "StigBenchmarkVersions",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "StigChecklistResults",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    ChecklistId = table.Column<int>(type: "INTEGER", nullable: false),
                    StigRuleId = table.Column<int>(type: "INTEGER", nullable: false),
                    Status = table.Column<int>(type: "INTEGER", nullable: false),
                    FindingDetails = table.Column<string>(type: "TEXT", nullable: true),
                    Comments = table.Column<string>(type: "TEXT", nullable: true),
                    SeverityOverrideJustification = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: true),
                    SeverityOverride = table.Column<int>(type: "INTEGER", nullable: true),
                    ModifiedById = table.Column<int>(type: "INTEGER", nullable: true),
                    LastModifiedDate = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_StigChecklistResults", x => x.Id);
                    table.ForeignKey(
                        name: "FK_StigChecklistResults_StigChecklists_ChecklistId",
                        column: x => x.ChecklistId,
                        principalTable: "StigChecklists",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_StigChecklistResults_StigRules_StigRuleId",
                        column: x => x.StigRuleId,
                        principalTable: "StigRules",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_StigChecklistResults_Users_ModifiedById",
                        column: x => x.ModifiedById,
                        principalTable: "Users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                });

            migrationBuilder.CreateIndex(
                name: "IX_StigBenchmarks_CurrentVersionId",
                table: "StigBenchmarks",
                column: "CurrentVersionId");

            migrationBuilder.CreateIndex(
                name: "IX_StigBenchmarks_StigId",
                table: "StigBenchmarks",
                column: "StigId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_StigBenchmarks_Title",
                table: "StigBenchmarks",
                column: "Title");

            migrationBuilder.CreateIndex(
                name: "IX_StigBenchmarkVersions_StigBenchmarkId",
                table: "StigBenchmarkVersions",
                column: "StigBenchmarkId");

            migrationBuilder.CreateIndex(
                name: "IX_StigBenchmarkVersions_StigBenchmarkId_Version_Release",
                table: "StigBenchmarkVersions",
                columns: new[] { "StigBenchmarkId", "Version", "Release" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_StigChecklistResults_ChecklistId",
                table: "StigChecklistResults",
                column: "ChecklistId");

            migrationBuilder.CreateIndex(
                name: "IX_StigChecklistResults_ChecklistId_StigRuleId",
                table: "StigChecklistResults",
                columns: new[] { "ChecklistId", "StigRuleId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_StigChecklistResults_ModifiedById",
                table: "StigChecklistResults",
                column: "ModifiedById");

            migrationBuilder.CreateIndex(
                name: "IX_StigChecklistResults_Status",
                table: "StigChecklistResults",
                column: "Status");

            migrationBuilder.CreateIndex(
                name: "IX_StigChecklistResults_StigRuleId",
                table: "StigChecklistResults",
                column: "StigRuleId");

            migrationBuilder.CreateIndex(
                name: "IX_StigChecklists_BenchmarkVersionId",
                table: "StigChecklists",
                column: "BenchmarkVersionId");

            migrationBuilder.CreateIndex(
                name: "IX_StigChecklists_CreatedById",
                table: "StigChecklists",
                column: "CreatedById");

            migrationBuilder.CreateIndex(
                name: "IX_StigChecklists_HostId",
                table: "StigChecklists",
                column: "HostId");

            migrationBuilder.CreateIndex(
                name: "IX_StigChecklists_LastModifiedById",
                table: "StigChecklists",
                column: "LastModifiedById");

            migrationBuilder.CreateIndex(
                name: "IX_StigChecklists_Status",
                table: "StigChecklists",
                column: "Status");

            migrationBuilder.CreateIndex(
                name: "IX_StigRules_BenchmarkVersionId",
                table: "StigRules",
                column: "BenchmarkVersionId");

            migrationBuilder.CreateIndex(
                name: "IX_StigRules_BenchmarkVersionId_VulnId",
                table: "StigRules",
                columns: new[] { "BenchmarkVersionId", "VulnId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_StigRules_RuleId",
                table: "StigRules",
                column: "RuleId");

            migrationBuilder.CreateIndex(
                name: "IX_StigRules_Severity",
                table: "StigRules",
                column: "Severity");

            migrationBuilder.CreateIndex(
                name: "IX_StigRules_VulnId",
                table: "StigRules",
                column: "VulnId");

            migrationBuilder.AddForeignKey(
                name: "FK_StigBenchmarks_StigBenchmarkVersions_CurrentVersionId",
                table: "StigBenchmarks",
                column: "CurrentVersionId",
                principalTable: "StigBenchmarkVersions",
                principalColumn: "Id",
                onDelete: ReferentialAction.SetNull);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_StigBenchmarks_StigBenchmarkVersions_CurrentVersionId",
                table: "StigBenchmarks");

            migrationBuilder.DropTable(
                name: "StigChecklistResults");

            migrationBuilder.DropTable(
                name: "StigChecklists");

            migrationBuilder.DropTable(
                name: "StigRules");

            migrationBuilder.DropTable(
                name: "StigBenchmarkVersions");

            migrationBuilder.DropTable(
                name: "StigBenchmarks");
        }
    }
}
