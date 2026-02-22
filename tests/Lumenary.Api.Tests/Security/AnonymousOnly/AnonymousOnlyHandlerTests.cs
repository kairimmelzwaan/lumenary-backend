using System.Security.Claims;
using Lumenary.Api.Security.AnonymousOnly;
using Microsoft.AspNetCore.Authorization;

namespace Lumenary.Api.Tests.Security.AnonymousOnly;

public sealed class AnonymousOnlyHandlerTests
{
    [Fact]
    public async Task HandleRequirementAsync_WhenUserIsAnonymous_ThenRequirementSucceeds()
    {
        var requirement = new AnonymousOnlyRequirement();
        var context = new AuthorizationHandlerContext(
            [requirement],
            new ClaimsPrincipal(new ClaimsIdentity()),
            resource: null);
        var handler = new AnonymousOnlyHandler();

        await handler.HandleAsync(context);

        Assert.True(context.HasSucceeded);
    }

    [Fact]
    public async Task HandleRequirementAsync_WhenUserIsAuthenticated_ThenRequirementDoesNotSucceed()
    {
        var requirement = new AnonymousOnlyRequirement();
        var authenticatedIdentity = new ClaimsIdentity(
            [new Claim(ClaimTypes.NameIdentifier, Guid.NewGuid().ToString())],
            authenticationType: "TestAuth");
        var context = new AuthorizationHandlerContext(
            [requirement],
            new ClaimsPrincipal(authenticatedIdentity),
            resource: null);
        var handler = new AnonymousOnlyHandler();

        await handler.HandleAsync(context);

        Assert.False(context.HasSucceeded);
    }
}
