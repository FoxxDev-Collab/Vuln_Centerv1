namespace VulnMgmt.Web.Models.Domain;

public enum Severity
{
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4
}

public enum AssetType
{
    Unknown = 0,
    Server = 1,
    Workstation = 2,
    NetworkDevice = 3,
    Printer = 4,
    MobileDevice = 5,
    VirtualMachine = 6,
    Container = 7,
    Other = 99
}

public enum HostStatus
{
    Unknown = 0,
    Active = 1,
    Inactive = 2,
    Decommissioned = 3
}

public enum RemediationStatus
{
    Open = 0,
    InProgress = 1,
    Remediated = 2,
    Accepted = 3,
    FalsePositive = 4
}

public enum UserRole
{
    Auditor = 0,    // Read-only access
    SysAdmin = 1,   // View all, update remediation status
    ISSO = 2,       // Create/edit scans, import, export - cannot manage sites/hosts
    ISSM = 3,       // Full access to sites, hosts, scans, imports, exports
    Admin = 4       // Super user - full system access including user management
}

// STIG-related enums
public enum StigSeverity
{
    Low = 1,        // CAT III
    Medium = 2,     // CAT II
    High = 3        // CAT I
}

public enum StigResultStatus
{
    NotReviewed = 0,
    Open = 1,
    NotAFinding = 2,
    NotApplicable = 3
}

public enum ChecklistStatus
{
    Draft = 0,
    InProgress = 1,
    Complete = 2
}
