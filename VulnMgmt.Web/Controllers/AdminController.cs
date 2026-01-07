using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using VulnMgmt.Web.Models.Domain;
using VulnMgmt.Web.Models.ViewModels;
using VulnMgmt.Web.Services;

namespace VulnMgmt.Web.Controllers;

[Authorize(Policy = "ManagerOrAbove")]
public class AdminController : Controller
{
    private readonly IUserService _userService;
    private readonly ILogger<AdminController> _logger;

    public AdminController(IUserService userService, ILogger<AdminController> logger)
    {
        _userService = userService;
        _logger = logger;
    }

    public async Task<IActionResult> Users()
    {
        var users = await _userService.GetAllAsync();
        return View(users);
    }

    public IActionResult CreateUser()
    {
        return View(new UserCreateViewModel());
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> CreateUser(UserCreateViewModel model)
    {
        if (!model.IsWindowsAuth && string.IsNullOrEmpty(model.Password))
        {
            ModelState.AddModelError("Password", "Password is required for local accounts.");
        }

        if (await _userService.UsernameExistsAsync(model.Username))
        {
            ModelState.AddModelError("Username", "This username is already taken.");
        }

        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var user = new User
        {
            Username = model.Username,
            DisplayName = model.DisplayName ?? model.Username,
            Email = model.Email,
            Phone = model.Phone,
            Role = model.Role,
            IsWindowsAuth = model.IsWindowsAuth,
            IsActive = model.IsActive
        };

        await _userService.CreateAsync(user, model.Password);
        _logger.LogInformation("User {Username} created by {Admin}", user.Username, User.Identity?.Name);

        TempData["Success"] = $"User '{user.Username}' created successfully.";
        return RedirectToAction(nameof(Users));
    }

    public async Task<IActionResult> EditUser(int id)
    {
        var user = await _userService.GetByIdAsync(id);
        if (user == null)
        {
            return NotFound();
        }

        var model = new UserEditViewModel
        {
            Id = user.Id,
            Username = user.Username,
            DisplayName = user.DisplayName,
            Email = user.Email,
            Phone = user.Phone,
            Role = user.Role,
            IsWindowsAuth = user.IsWindowsAuth,
            IsActive = user.IsActive,
            CreatedDate = user.CreatedDate,
            LastLoginDate = user.LastLoginDate
        };

        return View(model);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> EditUser(int id, UserEditViewModel model)
    {
        if (id != model.Id)
        {
            return BadRequest();
        }

        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var user = await _userService.GetByIdAsync(id);
        if (user == null)
        {
            return NotFound();
        }

        // Username is read-only in edit, don't update it
        user.DisplayName = model.DisplayName;
        user.Email = model.Email;
        user.Phone = model.Phone;
        user.Role = model.Role;
        user.IsWindowsAuth = model.IsWindowsAuth;
        user.IsActive = model.IsActive;

        await _userService.UpdateAsync(user);
        _logger.LogInformation("User {Username} updated by {Admin}", user.Username, User.Identity?.Name);

        TempData["Success"] = $"User '{user.Username}' updated successfully.";
        return RedirectToAction(nameof(Users));
    }

    public async Task<IActionResult> ChangePassword(int id)
    {
        var user = await _userService.GetByIdAsync(id);
        if (user == null)
        {
            return NotFound();
        }

        if (user.IsWindowsAuth)
        {
            TempData["Error"] = "Cannot change password for Windows/AD authenticated users.";
            return RedirectToAction(nameof(EditUser), new { id });
        }

        var model = new ChangePasswordViewModel
        {
            UserId = user.Id,
            Username = user.Username
        };

        return View(model);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ChangePassword(ChangePasswordViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var user = await _userService.GetByIdAsync(model.UserId);
        if (user == null)
        {
            return NotFound();
        }

        if (user.IsWindowsAuth)
        {
            TempData["Error"] = "Cannot change password for Windows/AD authenticated users.";
            return RedirectToAction(nameof(EditUser), new { id = model.UserId });
        }

        await _userService.UpdatePasswordAsync(model.UserId, model.NewPassword);
        _logger.LogInformation("Password changed for user {Username} by {Admin}", user.Username, User.Identity?.Name);

        TempData["Success"] = $"Password changed successfully for '{user.Username}'.";
        return RedirectToAction(nameof(EditUser), new { id = model.UserId });
    }

    [Authorize(Policy = "AdminOnly")]
    public async Task<IActionResult> DeleteUser(int id)
    {
        var user = await _userService.GetByIdAsync(id);
        if (user == null)
        {
            return NotFound();
        }

        // Prevent deleting yourself
        var currentUsername = User.Identity?.Name;
        if (user.Username.Equals(currentUsername, StringComparison.OrdinalIgnoreCase))
        {
            TempData["Error"] = "You cannot delete your own account.";
            return RedirectToAction(nameof(Users));
        }

        return View(user);
    }

    [HttpPost, ActionName("DeleteUser")]
    [ValidateAntiForgeryToken]
    [Authorize(Policy = "AdminOnly")]
    public async Task<IActionResult> DeleteUserConfirmed(int id)
    {
        var user = await _userService.GetByIdAsync(id);
        if (user == null)
        {
            return NotFound();
        }

        // Prevent deleting yourself
        var currentUsername = User.Identity?.Name;
        if (user.Username.Equals(currentUsername, StringComparison.OrdinalIgnoreCase))
        {
            TempData["Error"] = "You cannot delete your own account.";
            return RedirectToAction(nameof(Users));
        }

        var username = user.Username;
        await _userService.DeleteAsync(id);
        _logger.LogInformation("User {Username} deleted by {Admin}", username, User.Identity?.Name);

        TempData["Success"] = $"User '{username}' deleted successfully.";
        return RedirectToAction(nameof(Users));
    }

    [Authorize(Policy = "AdminOnly")]
    public IActionResult AuditLogs()
    {
        // Placeholder for audit logs
        return View();
    }
}
