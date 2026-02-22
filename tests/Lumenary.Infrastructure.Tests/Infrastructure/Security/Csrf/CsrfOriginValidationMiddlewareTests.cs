using Lumenary.Infrastructure.Security.Csrf;
using Lumenary.Application.Common.Options;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Lumenary.Tests.Infrastructure.Security.Csrf;

public sealed class CsrfOriginValidationMiddlewareTests
{
    [Theory]
    [InlineData("GET")]
    [InlineData("HEAD")]
    [InlineData("OPTIONS")]
    [InlineData("TRACE")]
    public async Task InvokeAsync_WhenMethodIsSafe_ThenBypassesValidation(string method)
    {
        var nextCalled = false;
        var sut = CreateSut(next: _ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        });

        var context = CreateContext(method, hasSessionCookie: true);

        await sut.InvokeAsync(context);

        Assert.True(nextCalled);
        Assert.Equal(StatusCodes.Status200OK, context.Response.StatusCode);
    }

    [Fact]
    public async Task InvokeAsync_WhenUnsafeMethodWithoutSessionCookie_ThenBypassesValidation()
    {
        var nextCalled = false;
        var sut = CreateSut(next: _ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        });

        var context = CreateContext(HttpMethods.Post, hasSessionCookie: false);

        await sut.InvokeAsync(context);

        Assert.True(nextCalled);
        Assert.Equal(StatusCodes.Status200OK, context.Response.StatusCode);
    }

    [Fact]
    public async Task InvokeAsync_WhenUnsafeMethodWithSessionCookieAndNoOriginOrReferer_ThenReturnsForbidden()
    {
        var nextCalled = false;
        var sut = CreateSut(next: _ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        });

        var context = CreateContext(HttpMethods.Post, hasSessionCookie: true);

        await sut.InvokeAsync(context);

        Assert.False(nextCalled);
        Assert.Equal(StatusCodes.Status403Forbidden, context.Response.StatusCode);
    }

    [Fact]
    public async Task InvokeAsync_WhenOriginMatchesRequestOrigin_ThenAllowsRequest()
    {
        var nextCalled = false;
        var sut = CreateSut(next: _ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        });

        var context = CreateContext(HttpMethods.Post, hasSessionCookie: true);
        context.Request.Headers.Origin = "https://api.example.com";

        await sut.InvokeAsync(context);

        Assert.True(nextCalled);
        Assert.Equal(StatusCodes.Status200OK, context.Response.StatusCode);
    }

    [Fact]
    public async Task InvokeAsync_WhenOriginIsInAllowlist_ThenAllowsRequest()
    {
        var nextCalled = false;
        var sut = CreateSut(
            next: _ =>
            {
                nextCalled = true;
                return Task.CompletedTask;
            },
            csrfAllowedOrigins: ["https://trusted.example.com/"]);

        var context = CreateContext(HttpMethods.Post, hasSessionCookie: true);
        context.Request.Headers.Origin = "https://trusted.example.com";

        await sut.InvokeAsync(context);

        Assert.True(nextCalled);
        Assert.Equal(StatusCodes.Status200OK, context.Response.StatusCode);
    }

    [Fact]
    public async Task InvokeAsync_WhenOriginIsDisallowed_ThenReturnsForbidden()
    {
        var nextCalled = false;
        var sut = CreateSut(next: _ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        });

        var context = CreateContext(HttpMethods.Post, hasSessionCookie: true);
        context.Request.Headers.Origin = "https://evil.example.com";

        await sut.InvokeAsync(context);

        Assert.False(nextCalled);
        Assert.Equal(StatusCodes.Status403Forbidden, context.Response.StatusCode);
    }

    [Fact]
    public async Task InvokeAsync_WhenOriginMissingAndRefererMatchesSameOrigin_ThenAllowsRequest()
    {
        var nextCalled = false;
        var sut = CreateSut(next: _ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        });

        var context = CreateContext(HttpMethods.Post, hasSessionCookie: true);
        context.Request.Headers.Referer = "https://api.example.com/path?x=1";

        await sut.InvokeAsync(context);

        Assert.True(nextCalled);
        Assert.Equal(StatusCodes.Status200OK, context.Response.StatusCode);
    }

    [Fact]
    public async Task InvokeAsync_WhenOriginIsLiteralNull_ThenReturnsForbidden()
    {
        var nextCalled = false;
        var sut = CreateSut(next: _ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        });

        var context = CreateContext(HttpMethods.Post, hasSessionCookie: true);
        context.Request.Headers.Origin = "null";

        await sut.InvokeAsync(context);

        Assert.False(nextCalled);
        Assert.Equal(StatusCodes.Status403Forbidden, context.Response.StatusCode);
    }

    [Fact]
    public async Task InvokeAsync_WhenOriginIsMalformed_ThenReturnsForbidden()
    {
        var nextCalled = false;
        var sut = CreateSut(next: _ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        });

        var context = CreateContext(HttpMethods.Post, hasSessionCookie: true);
        context.Request.Headers.Origin = "https://%zz";

        await sut.InvokeAsync(context);

        Assert.False(nextCalled);
        Assert.Equal(StatusCodes.Status403Forbidden, context.Response.StatusCode);
    }

    [Fact]
    public async Task InvokeAsync_WhenOriginUsesNonHttpScheme_ThenReturnsForbidden()
    {
        var nextCalled = false;
        var sut = CreateSut(next: _ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        });

        var context = CreateContext(HttpMethods.Post, hasSessionCookie: true);
        context.Request.Headers.Origin = "chrome-extension://extension-id";

        await sut.InvokeAsync(context);

        Assert.False(nextCalled);
        Assert.Equal(StatusCodes.Status403Forbidden, context.Response.StatusCode);
    }

    private static CsrfOriginValidationMiddleware CreateSut(
        RequestDelegate next,
        string[]? csrfAllowedOrigins = null)
    {
        var options = Options.Create(new AuthOptions
        {
            CookieName = "lumenary_session",
            CsrfAllowedOrigins = csrfAllowedOrigins ?? []
        });

        return new CsrfOriginValidationMiddleware(next, options, NullLogger<CsrfOriginValidationMiddleware>.Instance);
    }

    private static DefaultHttpContext CreateContext(string method, bool hasSessionCookie)
    {
        var context = new DefaultHttpContext();
        context.Request.Method = method;
        context.Request.Scheme = "https";
        context.Request.Host = new HostString("api.example.com");

        if (hasSessionCookie)
            context.Request.Headers.Cookie = "lumenary_session=test-token";

        return context;
    }
}
