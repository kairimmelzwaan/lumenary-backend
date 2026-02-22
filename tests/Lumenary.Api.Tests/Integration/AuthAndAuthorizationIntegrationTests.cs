using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;

namespace Lumenary.Api.Tests.Integration;

public sealed class AuthAndAuthorizationIntegrationTests
{
    [Fact]
    public async Task GetAccountMe_WhenUnauthenticated_ThenReturnsUnauthorized()
    {
        await using var factory = new ApiWebApplicationFactory();
        using var client = CreateClient(factory);

        var response = await client.GetAsync("/api/account/me");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Register_WhenPayloadIsInvalid_ThenReturnsBadRequest()
    {
        await using var factory = new ApiWebApplicationFactory();
        using var client = CreateClient(factory);

        var payload = new
        {
            name = "   ",
            email = "not-an-email",
            password = "weak",
            phoneE164 = "invalid-phone",
            dateOfBirth = DateTime.UtcNow.Date.AddDays(1)
        };

        var response = await client.PostAsJsonAsync("/api/auth/register", payload);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task UpdateProfile_WhenPayloadIsInvalidAndUserIsAuthenticated_ThenReturnsBadRequest()
    {
        await using var factory = new AuthenticatedApiWebApplicationFactory();
        using var client = CreateClient(factory);

        var payload = new
        {
            name = "   ",
            dateOfBirth = DateTime.UtcNow.Date.AddDays(1)
        };

        var response = await client.PatchAsJsonAsync("/api/account", payload);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    private static HttpClient CreateClient(ApiWebApplicationFactory factory)
        => factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false
        });
}
