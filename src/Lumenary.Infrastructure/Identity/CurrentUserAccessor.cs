using System.Security.Claims;
using Lumenary.Features.Auth.Users;

namespace Lumenary.Infrastructure.Identity;

public sealed class CurrentUserAccessor(IHttpContextAccessor httpContextAccessor) : ICurrentUserAccessor
{
    public bool TryGetUserId(out Guid userId)
    {
        userId = Guid.Empty;
        var userIdValue = httpContextAccessor.HttpContext?.User.FindFirstValue(ClaimTypes.NameIdentifier);
        return !string.IsNullOrWhiteSpace(userIdValue) && Guid.TryParse(userIdValue, out userId);
    }

    public bool TryGetSessionId(out Guid sessionId)
    {
        sessionId = Guid.Empty;
        var sessionIdValue = httpContextAccessor.HttpContext?.User.FindFirstValue(ClaimTypes.Sid);
        return !string.IsNullOrWhiteSpace(sessionIdValue) && Guid.TryParse(sessionIdValue, out sessionId);
    }

    public bool TryGetRole(out string? role)
    {
        role = httpContextAccessor.HttpContext?.User.FindFirstValue(ClaimTypes.Role);
        return !string.IsNullOrWhiteSpace(role);
    }
}
