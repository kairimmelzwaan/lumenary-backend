using System.Text;
using Lumenary.Application.Common.Options;
using Lumenary.Infrastructure.RateLimiting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Options;

namespace Lumenary.Tests.Infrastructure.RateLimiting;

public sealed class AuthIdentifierRateLimitingMiddlewareTests
{
    [Fact]
    public async Task InvokeAsync_WhenEndpointPolicyIsNotAuth_ThenBypassesRateLimiting()
    {
        await using var rateLimiter = CreateRateLimiter();

        var nextCalled = false;
        var sut = new AuthIdentifierRateLimitingMiddleware(
            _ =>
            {
                nextCalled = true;
                return Task.CompletedTask;
            },
            rateLimiter);

        var context = CreateContext("/v1/auth/login", "?email=user@example.com", policyName: "Other");
        using var _ = await rateLimiter.AcquireAsync("/v1/auth/login:user@example.com", CancellationToken.None);

        await sut.InvokeAsync(context);

        Assert.True(nextCalled);
        Assert.Equal(StatusCodes.Status200OK, context.Response.StatusCode);
    }

    [Fact]
    public async Task InvokeAsync_WhenAuthPolicyAndLeaseIsAcquired_ThenCallsNext()
    {
        await using var rateLimiter = CreateRateLimiter();

        var nextCalled = false;
        var sut = new AuthIdentifierRateLimitingMiddleware(
            _ =>
            {
                nextCalled = true;
                return Task.CompletedTask;
            },
            rateLimiter);

        var context = CreateContext("/v1/auth/login", "?email=USER@example.com", policyName: "Auth");

        await sut.InvokeAsync(context);

        Assert.True(nextCalled);
        Assert.Equal(StatusCodes.Status200OK, context.Response.StatusCode);
    }

    [Fact]
    public async Task InvokeAsync_WhenAuthPolicyAndLeaseIsDenied_ThenReturnsTooManyRequests()
    {
        await using var rateLimiter = CreateRateLimiter();

        var nextCalled = false;
        var sut = new AuthIdentifierRateLimitingMiddleware(
            _ =>
            {
                nextCalled = true;
                return Task.CompletedTask;
            },
            rateLimiter);

        using var _ = await rateLimiter.AcquireAsync("/v1/auth/login:user@example.com", CancellationToken.None);
        var context = CreateContext("/v1/auth/login", "?email=user@example.com", policyName: "Auth");

        await sut.InvokeAsync(context);

        Assert.False(nextCalled);
        Assert.Equal(StatusCodes.Status429TooManyRequests, context.Response.StatusCode);
    }

    [Fact]
    public async Task InvokeAsync_WhenJsonBodyContainsEmail_ThenUsesNormalizedEmailIdentifier()
    {
        await using var rateLimiter = CreateRateLimiter();

        var nextCallCount = 0;
        var sut = new AuthIdentifierRateLimitingMiddleware(
            _ =>
            {
                nextCallCount += 1;
                return Task.CompletedTask;
            },
            rateLimiter);

        var first = CreateJsonBodyContext("/v1/auth/login", "{\"email\":\"  USER@Example.com  \"}");
        var second = CreateJsonBodyContext("/v1/auth/login", "{\"email\":\"user@example.com\"}");

        await sut.InvokeAsync(first);
        await sut.InvokeAsync(second);

        Assert.Equal(StatusCodes.Status200OK, first.Response.StatusCode);
        Assert.Equal(StatusCodes.Status429TooManyRequests, second.Response.StatusCode);
        Assert.Equal(1, nextCallCount);
    }

    [Fact]
    public async Task InvokeAsync_WhenJsonBodyContainsPhone_ThenUsesNormalizedPhoneIdentifier()
    {
        await using var rateLimiter = CreateRateLimiter();

        var nextCallCount = 0;
        var sut = new AuthIdentifierRateLimitingMiddleware(
            _ =>
            {
                nextCallCount += 1;
                return Task.CompletedTask;
            },
            rateLimiter);

        var first = CreateJsonBodyContext("/v1/auth/login", "{\"phoneE164\":\"00 31 6-1234-5678\"}");
        var second = CreateJsonBodyContext("/v1/auth/login", "{\"phoneE164\":\"+31612345678\"}");

        await sut.InvokeAsync(first);
        await sut.InvokeAsync(second);

        Assert.Equal(StatusCodes.Status200OK, first.Response.StatusCode);
        Assert.Equal(StatusCodes.Status429TooManyRequests, second.Response.StatusCode);
        Assert.Equal(1, nextCallCount);
    }

    [Fact]
    public async Task InvokeAsync_WhenJsonBodyContainsChallengeId_ThenUsesChallengeIdIdentifier()
    {
        await using var rateLimiter = CreateRateLimiter();

        var nextCallCount = 0;
        var sut = new AuthIdentifierRateLimitingMiddleware(
            _ =>
            {
                nextCallCount += 1;
                return Task.CompletedTask;
            },
            rateLimiter);

        var challengeId = Guid.NewGuid();
        var first = CreateJsonBodyContext("/v1/auth/login", $"{{\"challengeId\":\"{challengeId}\"}}");
        var second = CreateJsonBodyContext("/v1/auth/login", $"{{\"challengeId\":\"{challengeId.ToString().ToUpperInvariant()}\"}}");

        await sut.InvokeAsync(first);
        await sut.InvokeAsync(second);

        Assert.Equal(StatusCodes.Status200OK, first.Response.StatusCode);
        Assert.Equal(StatusCodes.Status429TooManyRequests, second.Response.StatusCode);
        Assert.Equal(1, nextCallCount);
    }

    [Fact]
    public async Task InvokeAsync_WhenQueryEmailIsEmptyAndBodyContainsEmail_ThenUsesBodyEmailIdentifier()
    {
        await using var rateLimiter = CreateRateLimiter();

        var nextCallCount = 0;
        var sut = new AuthIdentifierRateLimitingMiddleware(
            _ =>
            {
                nextCallCount += 1;
                return Task.CompletedTask;
            },
            rateLimiter);

        var first = CreateJsonBodyContext("/v1/auth/login", "{\"email\":\"user@example.com\"}");
        first.Request.QueryString = new QueryString("?email=");
        var second = CreateJsonBodyContext("/v1/auth/login", "{\"email\":\"USER@example.com\"}");
        second.Request.QueryString = new QueryString("?email=");

        await sut.InvokeAsync(first);
        await sut.InvokeAsync(second);

        Assert.Equal(StatusCodes.Status200OK, first.Response.StatusCode);
        Assert.Equal(StatusCodes.Status429TooManyRequests, second.Response.StatusCode);
        Assert.Equal(1, nextCallCount);
    }

    [Fact]
    public async Task InvokeAsync_WhenContentLengthExceedsLimit_ThenBypassesIdentifierExtractionSafely()
    {
        await using var rateLimiter = CreateRateLimiter();

        var nextCalled = false;
        var sut = new AuthIdentifierRateLimitingMiddleware(
            _ =>
            {
                nextCalled = true;
                return Task.CompletedTask;
            },
            rateLimiter);

        using var _ = await rateLimiter.AcquireAsync("/v1/auth/login:user@example.com", CancellationToken.None);

        var context = CreateJsonBodyContext("/v1/auth/login", "{\"email\":\"user@example.com\"}");
        context.Request.ContentLength = (32 * 1024) + 1;

        await sut.InvokeAsync(context);

        Assert.True(nextCalled);
        Assert.Equal(StatusCodes.Status200OK, context.Response.StatusCode);
    }

    [Fact]
    public async Task InvokeAsync_WhenBodyExceedsLimitWithoutContentLength_ThenBypassesIdentifierExtractionSafely()
    {
        await using var rateLimiter = CreateRateLimiter();

        var nextCalled = false;
        var sut = new AuthIdentifierRateLimitingMiddleware(
            _ =>
            {
                nextCalled = true;
                return Task.CompletedTask;
            },
            rateLimiter);

        using var _ = await rateLimiter.AcquireAsync("/v1/auth/login:user@example.com", CancellationToken.None);

        var payload = "{\"email\":\"user@example.com\",\"padding\":\"" + new string('a', (32 * 1024) + 256) + "\"}";
        var context = CreateJsonBodyContext("/v1/auth/login", payload);

        await sut.InvokeAsync(context);

        Assert.True(nextCalled);
        Assert.Equal(StatusCodes.Status200OK, context.Response.StatusCode);
    }

    private static AuthIdentifierRateLimiter CreateRateLimiter()
    {
        var options = Options.Create(new AuthOptions
        {
            IdentifierRateLimit = new AuthOptions.IdentifierRateLimitOptions
            {
                PermitLimit = 1,
                WindowSeconds = 60,
                QueueLimit = 0
            }
        });

        return new AuthIdentifierRateLimiter(options);
    }

    private static DefaultHttpContext CreateContext(string path, string queryString, string policyName)
    {
        var context = new DefaultHttpContext();
        context.Request.Path = path;
        context.Request.QueryString = new QueryString(queryString);
        context.SetEndpoint(CreateEndpoint(policyName));
        return context;
    }

    private static DefaultHttpContext CreateJsonBodyContext(string path, string body)
    {
        var context = CreateContext(path, string.Empty, "Auth");
        context.Request.ContentType = "application/json";
        context.Request.Body = new MemoryStream(Encoding.UTF8.GetBytes(body));
        return context;
    }

    private static Endpoint CreateEndpoint(string policyName)
    {
        return new Endpoint(
            _ => Task.CompletedTask,
            new EndpointMetadataCollection(new EnableRateLimitingAttribute(policyName)),
            "test-endpoint");
    }
}
