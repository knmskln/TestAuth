using Microsoft.AspNetCore.Authorization;

namespace TestAuth.Helpers;

public class PermissionRequirement : IAuthorizationRequirement
{
    public string PermissionId { get; }

    public PermissionRequirement(string permissionId)
    {
        PermissionId = permissionId;
    }
}