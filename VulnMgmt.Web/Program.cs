using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;
using Serilog;
using VulnMgmt.Web.Data;
using VulnMgmt.Web.Services;

var builder = WebApplication.CreateBuilder(args);

// Configure Serilog
Log.Logger = new LoggerConfiguration()
    .ReadFrom.Configuration(builder.Configuration)
    .Enrich.FromLogContext()
    .WriteTo.Console()
    .CreateLogger();

builder.Host.UseSerilog();

// Add services to the container.
builder.Services.AddControllersWithViews();

// Add Entity Framework with SQLite
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection")));

// Register services
builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddScoped<ISiteService, SiteService>();
builder.Services.AddScoped<IHostService, HostService>();
builder.Services.AddScoped<IVulnerabilityService, VulnerabilityService>();
builder.Services.AddScoped<IUserService, UserService>();
builder.Services.AddScoped<IScanImportService, ScanImportService>();
builder.Services.AddScoped<IReportService, ReportService>();
builder.Services.AddScoped<IStigLibraryService, StigLibraryService>();
builder.Services.AddScoped<IStigChecklistService, StigChecklistService>();

// Configure authentication
var useWindowsAuth = builder.Configuration.GetValue<bool>("Authentication:UseWindowsAuth");

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/Account/Login";
        options.LogoutPath = "/Account/Logout";
        options.AccessDeniedPath = "/Account/AccessDenied";
        options.ExpireTimeSpan = TimeSpan.FromHours(8);
        options.SlidingExpiration = true;
    });

if (useWindowsAuth)
{
    builder.Services.AddAuthentication()
        .AddNegotiate();
}

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminOnly", policy => policy.RequireRole("Admin"));
    options.AddPolicy("ManagerOrAbove", policy => policy.RequireRole("Admin", "ISSM"));
    options.AddPolicy("UserOrAbove", policy => policy.RequireRole("Admin", "ISSM", "ISSO", "SysAdmin"));
    options.AddPolicy("CanView", policy => policy.RequireRole("Admin", "ISSM", "ISSO", "SysAdmin", "Auditor"));
    options.AddPolicy("CanEdit", policy => policy.RequireRole("Admin", "ISSM", "ISSO", "SysAdmin"));
});

var app = builder.Build();

// Initialize database
using (var scope = app.Services.CreateScope())
{
    var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    DbInitializer.Initialize(context);
}

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapStaticAssets();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}")
    .WithStaticAssets();

app.Run();
