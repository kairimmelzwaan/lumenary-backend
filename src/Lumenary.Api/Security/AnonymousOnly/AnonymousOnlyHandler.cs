using Microsoft.AspNetCore.Authorization;

namespace Lumenary.Api.Security.AnonymousOnly;

public sealed class AnonymousOnlyHandler : AuthorizationHandler<AnonymousOnlyRequirement>
{
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context,
        AnonymousOnlyRequirement requirement)
    {
        if (!(context.User?.Identity?.IsAuthenticated ?? false))
            context.Succeed(requirement);

        return Task.CompletedTask;
    }
}