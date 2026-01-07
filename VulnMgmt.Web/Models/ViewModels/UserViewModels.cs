using System.ComponentModel.DataAnnotations;
using VulnMgmt.Web.Models.Domain;

namespace VulnMgmt.Web.Models.ViewModels;

public class UserIndexViewModel
{
    public IEnumerable<UserListItem> Users { get; set; } = new List<UserListItem>();
    public int TotalCount { get; set; }
    public int ActiveCount { get; set; }
}

public class UserListItem
{
    public int Id { get; set; }
    public string Username { get; set; } = string.Empty;
    public string? DisplayName { get; set; }
    public string? Email { get; set; }
    public UserRole Role { get; set; }
    public bool IsWindowsAuth { get; set; }
    public bool IsActive { get; set; }
    public DateTime CreatedDate { get; set; }
    public DateTime? LastLoginDate { get; set; }
}

public class UserCreateViewModel
{
    [Required]
    [StringLength(100, MinimumLength = 3)]
    [RegularExpression(@"^[a-zA-Z0-9._-]+$", ErrorMessage = "Username can only contain letters, numbers, dots, underscores, and hyphens.")]
    public string Username { get; set; } = string.Empty;

    [StringLength(200)]
    [Display(Name = "Display Name")]
    public string? DisplayName { get; set; }

    [EmailAddress]
    [StringLength(200)]
    public string? Email { get; set; }

    [Phone]
    [StringLength(20)]
    public string? Phone { get; set; }

    [Required]
    public UserRole Role { get; set; } = UserRole.Auditor;

    [Display(Name = "Windows/AD Authentication")]
    public bool IsWindowsAuth { get; set; }

    [StringLength(100, MinimumLength = 8, ErrorMessage = "Password must be at least 8 characters.")]
    [DataType(DataType.Password)]
    public string? Password { get; set; }

    [Compare("Password", ErrorMessage = "Passwords do not match.")]
    [DataType(DataType.Password)]
    [Display(Name = "Confirm Password")]
    public string? ConfirmPassword { get; set; }

    [Display(Name = "Active")]
    public bool IsActive { get; set; } = true;
}

public class UserEditViewModel
{
    public int Id { get; set; }

    [Required]
    [StringLength(100, MinimumLength = 3)]
    [RegularExpression(@"^[a-zA-Z0-9._-]+$", ErrorMessage = "Username can only contain letters, numbers, dots, underscores, and hyphens.")]
    public string Username { get; set; } = string.Empty;

    [StringLength(200)]
    [Display(Name = "Display Name")]
    public string? DisplayName { get; set; }

    [EmailAddress]
    [StringLength(200)]
    public string? Email { get; set; }

    [Phone]
    [StringLength(20)]
    public string? Phone { get; set; }

    [Required]
    public UserRole Role { get; set; }

    [Display(Name = "Windows/AD Authentication")]
    public bool IsWindowsAuth { get; set; }

    [Display(Name = "Active")]
    public bool IsActive { get; set; }

    public DateTime CreatedDate { get; set; }
    public DateTime? LastLoginDate { get; set; }
}

public class ChangePasswordViewModel
{
    public int UserId { get; set; }
    public string Username { get; set; } = string.Empty;

    [Required]
    [StringLength(100, MinimumLength = 8, ErrorMessage = "Password must be at least 8 characters.")]
    [DataType(DataType.Password)]
    [Display(Name = "New Password")]
    public string NewPassword { get; set; } = string.Empty;

    [Required]
    [Compare("NewPassword", ErrorMessage = "Passwords do not match.")]
    [DataType(DataType.Password)]
    [Display(Name = "Confirm Password")]
    public string ConfirmPassword { get; set; } = string.Empty;
}
