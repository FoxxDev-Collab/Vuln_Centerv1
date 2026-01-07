using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Negotiate;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using VulnMgmt.Web.Models.ViewModels;
using VulnMgmt.Web.Services;

namespace VulnMgmt.Web.Controllers;

public class AccountController : Controller
{
    private readonly IAuthService _authService;
    private readonly IConfiguration _configuration;
    private readonly ILogger<AccountController> _logger;

    public AccountController(IAuthService authService, IConfiguration configuration, ILogger<AccountController> logger)
    {
        _authService = authService;
        _configuration = configuration;
        _logger = logger;
    }

    [HttpGet]
    [AllowAnonymous]
    public IActionResult Login(string? returnUrl = null)
    {
        // Check if already authenticated via cookie
        if (User.Identity?.IsAuthenticated == true &&
            User.Identity.AuthenticationType == CookieAuthenticationDefaults.AuthenticationScheme)
        {
            return RedirectToLocal(returnUrl);
        }

        ViewData["ReturnUrl"] = returnUrl;
        ViewData["UseWindowsAuth"] = _configuration.GetValue<bool>("Authentication:UseWindowsAuth");
        ViewData["AllowLocalFallback"] = _configuration.GetValue<bool>("Authentication:AllowLocalFallback");

        return View(new LoginViewModel { ReturnUrl = returnUrl });
    }

    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Login(LoginViewModel model)
    {
        ViewData["ReturnUrl"] = model.ReturnUrl;
        ViewData["UseWindowsAuth"] = _configuration.GetValue<bool>("Authentication:UseWindowsAuth");
        ViewData["AllowLocalFallback"] = _configuration.GetValue<bool>("Authentication:AllowLocalFallback");

        if (!ModelState.IsValid)
        {
            return View(model);
        }

        // Check if local auth is allowed
        if (!_configuration.GetValue<bool>("Authentication:AllowLocalFallback"))
        {
            ModelState.AddModelError(string.Empty, "Local authentication is not enabled. Please use Windows authentication.");
            return View(model);
        }

        var user = await _authService.AuthenticateAsync(model.Username, model.Password);
        if (user == null)
        {
            _logger.LogWarning("Failed login attempt for user: {Username}", model.Username);
            ModelState.AddModelError(string.Empty, "Invalid username or password.");
            return View(model);
        }

        _logger.LogInformation("User {Username} logged in via local auth", user.Username);
        await SignInUserAsync(user, model.RememberMe);

        return RedirectToLocal(model.ReturnUrl);
    }

    [HttpGet]
    [AllowAnonymous]
    public IActionResult WindowsLogin(string? returnUrl = null)
    {
        // Check if Windows auth is enabled
        if (!_configuration.GetValue<bool>("Authentication:UseWindowsAuth"))
        {
            return RedirectToAction("Login", new { returnUrl });
        }

        // Challenge for Windows authentication
        return Challenge(new AuthenticationProperties
        {
            RedirectUri = Url.Action("WindowsLoginCallback", new { returnUrl })
        }, NegotiateDefaults.AuthenticationScheme);
    }

    [HttpGet]
    [Authorize(AuthenticationSchemes = NegotiateDefaults.AuthenticationScheme)]
    public async Task<IActionResult> WindowsLoginCallback(string? returnUrl = null)
    {
        var windowsIdentity = User.Identity;
        if (windowsIdentity == null || !windowsIdentity.IsAuthenticated)
        {
            _logger.LogWarning("Windows authentication failed - no identity");
            TempData["Error"] = "Windows authentication failed. Please try again or use local login.";
            return RedirectToAction("Login", new { returnUrl });
        }

        var windowsUsername = windowsIdentity.Name;
        if (string.IsNullOrEmpty(windowsUsername))
        {
            _logger.LogWarning("Windows authentication failed - empty username");
            TempData["Error"] = "Windows authentication failed. Please try again.";
            return RedirectToAction("Login", new { returnUrl });
        }

        _logger.LogInformation("Windows authentication successful for: {Username}", windowsUsername);

        var user = await _authService.GetOrCreateWindowsUserAsync(windowsUsername);
        if (user == null)
        {
            _logger.LogWarning("Windows user {Username} is disabled", windowsUsername);
            TempData["Error"] = "Your account has been disabled. Please contact an administrator.";
            return RedirectToAction("Login", new { returnUrl });
        }

        _logger.LogInformation("User {Username} logged in via Windows auth with role {Role}", user.Username, user.Role);
        await SignInUserAsync(user, isPersistent: false);

        return RedirectToLocal(returnUrl);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Logout()
    {
        var username = User.Identity?.Name;
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        _logger.LogInformation("User {Username} logged out", username);
        return RedirectToAction("Index", "Home");
    }

    [HttpGet]
    [AllowAnonymous]
    public IActionResult AccessDenied(string? returnUrl = null)
    {
        _logger.LogWarning("Access denied for user {Username} to {ReturnUrl}", User.Identity?.Name, returnUrl);
        ViewData["ReturnUrl"] = returnUrl;
        return View();
    }

    private async Task SignInUserAsync(Models.Domain.User user, bool isPersistent)
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new(ClaimTypes.Name, user.Username),
            new(ClaimTypes.Role, user.Role.ToString()),
            new("DisplayName", user.DisplayName ?? user.Username),
            new("IsWindowsAuth", user.IsWindowsAuth.ToString())
        };

        if (!string.IsNullOrEmpty(user.Email))
        {
            claims.Add(new Claim(ClaimTypes.Email, user.Email));
        }

        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        var principal = new ClaimsPrincipal(identity);

        var authProperties = new AuthenticationProperties
        {
            IsPersistent = isPersistent,
            ExpiresUtc = isPersistent ? DateTimeOffset.UtcNow.AddDays(30) : DateTimeOffset.UtcNow.AddHours(8),
            AllowRefresh = true
        };

        await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal, authProperties);
    }

    private IActionResult RedirectToLocal(string? returnUrl)
    {
        if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
        {
            return Redirect(returnUrl);
        }
        return RedirectToAction("Index", "Home");
    }
}
