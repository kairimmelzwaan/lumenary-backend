using System.Security.Claims;
using System.Text.Encodings.Web;
using Lumenary.Application.Common.Options;
using Lumenary.Infrastructure.Auth.Sessions;
using Lumenary.Persistence;
using Lumenary.Domain.ValueObjects;
using Lumenary.Persistence.Entities;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Lumenary.Tests.Infrastructure.Auth.Sessions;

public sealed class SessionAuthenticationHandlerTests
{
    private const string SessionTokenKey = "01234567890123456789012345678901";

    [Fact]
    public async Task HandleAuthenticateAsync_WhenNoTokenProvided_ThenReturnsNoResult()
    {
        await using var dbContext = CreateDbContext();
        var context = CreateContext(dbContext);

        var handler = await CreateInitializedHandlerAsync(context);

        var result = await handler.AuthenticateAsync();

        Assert.True(result.None);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_WhenTokenFormatIsInvalid_ThenReturnsFail()
    {
        await using var dbContext = CreateDbContext();
        var context = CreateContext(dbContext);
        context.Request.Headers.Cookie = "lumenary_session=***invalid***";

        var handler = await CreateInitializedHandlerAsync(context);

        var result = await handler.AuthenticateAsync();

        Assert.False(result.Succeeded);
        Assert.Equal("Invalid session token.", result.Failure?.Message);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_WhenSessionDoesNotExist_ThenReturnsFail()
    {
        await using var dbContext = CreateDbContext();
        var context = CreateContext(dbContext);

        var token = SessionTokenUtilities.CreateToken(SessionTokenKey, out _);
        context.Request.Headers.Cookie = $"lumenary_session={token}";

        var handler = await CreateInitializedHandlerAsync(context);

        var result = await handler.AuthenticateAsync();

        Assert.False(result.Succeeded);
        Assert.Equal("Invalid session.", result.Failure?.Message);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_WhenSessionIsRevoked_ThenReturnsFail()
    {
        await using var dbContext = CreateDbContext();
        var token = await SeedSessionAsync(dbContext, revoked: true, expiresAt: DateTime.UtcNow.AddMinutes(10));

        var context = CreateContext(dbContext);
        context.Request.Headers.Cookie = $"lumenary_session={token}";

        var handler = await CreateInitializedHandlerAsync(context);

        var result = await handler.AuthenticateAsync();

        Assert.False(result.Succeeded);
        Assert.Equal("Session expired.", result.Failure?.Message);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_WhenSessionIsExpired_ThenReturnsFail()
    {
        await using var dbContext = CreateDbContext();
        var token = await SeedSessionAsync(dbContext, revoked: false, expiresAt: DateTime.UtcNow.AddMinutes(-1));

        var context = CreateContext(dbContext);
        context.Request.Headers.Cookie = $"lumenary_session={token}";

        var handler = await CreateInitializedHandlerAsync(context);

        var result = await handler.AuthenticateAsync();

        Assert.False(result.Succeeded);
        Assert.Equal("Session expired.", result.Failure?.Message);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_WhenUserIsInactive_ThenReturnsFail()
    {
        await using var dbContext = CreateDbContext();
        var token = await SeedSessionAsync(
            dbContext,
            revoked: false,
            expiresAt: DateTime.UtcNow.AddMinutes(10),
            isUserActive: false);

        var context = CreateContext(dbContext);
        context.Request.Headers.Cookie = $"lumenary_session={token}";

        var handler = await CreateInitializedHandlerAsync(context);

        var result = await handler.AuthenticateAsync();

        Assert.False(result.Succeeded);
        Assert.Equal("User inactive.", result.Failure?.Message);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_WhenUserIsUnverified_ThenReturnsFail()
    {
        await using var dbContext = CreateDbContext();
        var token = await SeedSessionAsync(
            dbContext,
            revoked: false,
            expiresAt: DateTime.UtcNow.AddMinutes(10),
            isUserVerified: false);

        var context = CreateContext(dbContext);
        context.Request.Headers.Cookie = $"lumenary_session={token}";

        var handler = await CreateInitializedHandlerAsync(context);

        var result = await handler.AuthenticateAsync();

        Assert.False(result.Succeeded);
        Assert.Equal("User unverified.", result.Failure?.Message);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_WhenSessionIsValid_ThenReturnsPrincipalWithExpectedClaims()
    {
        await using var dbContext = CreateDbContext();
        var session = await SeedSessionEntityAsync(
            dbContext,
            revoked: false,
            expiresAt: DateTime.UtcNow.AddMinutes(10));

        var token = SessionTokenUtilities.CreateToken(SessionTokenKey, out var tokenHash);
        session.SessionTokenHash = tokenHash;
        await dbContext.SaveChangesAsync();

        var context = CreateContext(dbContext);
        context.Request.Headers.Cookie = $"lumenary_session={token}";

        var handler = await CreateInitializedHandlerAsync(context);

        var result = await handler.AuthenticateAsync();

        Assert.True(result.Succeeded);
        Assert.NotNull(result.Principal);

        var principal = result.Principal!;
        Assert.Equal(session.UserId.ToString(), principal.FindFirstValue(ClaimTypes.NameIdentifier));
        Assert.Equal(UserRoles.Client, principal.FindFirstValue(ClaimTypes.Role));
        Assert.Equal(session.Id.ToString(), principal.FindFirstValue(ClaimTypes.Sid));
    }

    [Fact]
    public async Task HandleAuthenticateAsync_WhenBearerTokenIsProvided_ThenReturnsPrincipal()
    {
        await using var dbContext = CreateDbContext();
        var token = await SeedSessionAsync(dbContext, revoked: false, expiresAt: DateTime.UtcNow.AddMinutes(10));

        var context = CreateContext(dbContext);
        context.Request.Headers.Authorization = $"Bearer {token}";

        var handler = await CreateInitializedHandlerAsync(context);

        var result = await handler.AuthenticateAsync();

        Assert.True(result.Succeeded);
        Assert.NotNull(result.Principal);
    }

    private static async Task<string> SeedSessionAsync(
        AppDbContext dbContext,
        bool revoked,
        DateTime expiresAt,
        bool isUserActive = true,
        bool isUserVerified = true)
    {
        var session = await SeedSessionEntityAsync(dbContext, revoked, expiresAt, isUserActive, isUserVerified);
        var token = SessionTokenUtilities.CreateToken(SessionTokenKey, out var tokenHash);
        session.SessionTokenHash = tokenHash;
        await dbContext.SaveChangesAsync();
        return token;
    }

    private static async Task<Session> SeedSessionEntityAsync(
        AppDbContext dbContext,
        bool revoked,
        DateTime expiresAt,
        bool isUserActive = true,
        bool isUserVerified = true)
    {
        var now = DateTime.UtcNow;
        var user = new User
        {
            Id = Guid.NewGuid(),
            Name = "session-user",
            Email = $"{Guid.NewGuid():N}@example.test",
            PhoneE164 = "+31612345678",
            PasswordHash = "hash",
            Role = UserRoles.Client,
            MustChangePassword = false,
            IsActive = isUserActive,
            IsVerified = isUserVerified,
            CreatedAt = now,
            UpdatedAt = now
        };

        var session = new Session
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            User = user,
            SessionTokenHash = Guid.NewGuid().ToByteArray(),
            CreatedAt = now,
            LastSeenAt = now,
            ExpiresAt = expiresAt,
            RevokedAt = revoked ? now : null,
            UserAgent = "xunit",
            IpAddress = "127.0.0.1"
        };

        dbContext.Users.Add(user);
        dbContext.Sessions.Add(session);
        await dbContext.SaveChangesAsync();

        return session;
    }

    private static async Task<SessionAuthenticationHandler> CreateInitializedHandlerAsync(HttpContext context)
    {
        var optionsMonitor = new StaticOptionsMonitor<AuthenticationSchemeOptions>(new AuthenticationSchemeOptions());
        var handler = new SessionAuthenticationHandler(
            optionsMonitor,
            NullLoggerFactory.Instance,
            UrlEncoder.Default,
            Options.Create(new AuthOptions
            {
                CookieName = "lumenary_session",
                SessionTokenKey = SessionTokenKey
            }));

        var scheme = new AuthenticationScheme(
            SessionAuthenticationDefaults.Scheme,
            SessionAuthenticationDefaults.Scheme,
            typeof(SessionAuthenticationHandler));

        await handler.InitializeAsync(scheme, context);
        return handler;
    }

    private static DefaultHttpContext CreateContext(AppDbContext dbContext)
    {
        var context = new DefaultHttpContext();

        var services = new ServiceCollection()
            .AddSingleton(dbContext)
            .BuildServiceProvider();

        context.RequestServices = services;
        return context;
    }

    private static AppDbContext CreateDbContext()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseInMemoryDatabase($"session-auth-handler-tests-{Guid.NewGuid():N}")
            .Options;

        var dbContext = new AppDbContext(options);
        dbContext.Database.EnsureCreated();
        return dbContext;
    }

    private sealed class StaticOptionsMonitor<TOptions>(TOptions currentValue) : IOptionsMonitor<TOptions>
        where TOptions : class
    {
        public TOptions CurrentValue => currentValue;

        public TOptions Get(string? name) => currentValue;

        public IDisposable OnChange(Action<TOptions, string?> listener)
            => NoopDisposable.Instance;
    }

    private sealed class NoopDisposable : IDisposable
    {
        public static readonly NoopDisposable Instance = new();

        public void Dispose()
        {
        }
    }
}
