using Lumenary.Features.Auth.Challenges;
using Lumenary.Infrastructure.Identity;
using Lumenary.Persistence;
using Lumenary.Features.Account.Models;
using Lumenary.Features.Auth.Models;
using Lumenary.Persistence.Entities;
using Lumenary.Features.Account.Services;
using Lumenary.Features.Auth.Services;
using Lumenary.Common.Results;
using Lumenary.Features.Auth.Users;
using Lumenary.Application.Common.Options;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Lumenary.Tests.Features.Account.Services;

public sealed class AccountServiceTests
{
    private readonly PasswordHasher<User> _passwordHasher = new();

    [Fact]
    public async Task ChangePasswordAsync_WhenCurrentSessionIdIsAvailable_ThenRevokesOnlyOtherActiveSessions()
    {
        await using var dbContext = CreateDbContext();
        var user = await SeedUserAsync(dbContext, "password-current@example.com", "OldPassword!1", mustChangePassword: true);

        var currentSession = await SeedSessionAsync(dbContext, user.Id, revoked: false);
        var otherActiveSession = await SeedSessionAsync(dbContext, user.Id, revoked: false);
        var alreadyRevokedSession = await SeedSessionAsync(dbContext, user.Id, revoked: true);

        var currentUser = new TestCurrentUserAccessor { UserId = user.Id, SessionId = currentSession.Id };
        var sessionService = new TestSessionService();
        var challengeService = new TestAuthChallengeService();
        var userLookup = new TestUserLookupService(dbContext);

        var sut = new AccountService(
            dbContext,
            challengeService,
            sessionService,
            currentUser,
            userLookup,
            _passwordHasher,
            Options.Create(new AuthOptions()));

        var result = await sut.ChangePasswordAsync(
            new PasswordChangeRequest("OldPassword!1", "N3wPassword!2"),
            CancellationToken.None);

        Assert.Equal(ResultStatus.Ok, result.Status);

        var refreshedUser = await dbContext.Users.SingleAsync(u => u.Id == user.Id);
        Assert.False(refreshedUser.MustChangePassword);
        Assert.NotEqual(PasswordVerificationResult.Failed,
            _passwordHasher.VerifyHashedPassword(refreshedUser, refreshedUser.PasswordHash, "N3wPassword!2"));

        var refreshedCurrentSession = await dbContext.Sessions.SingleAsync(s => s.Id == currentSession.Id);
        var refreshedOtherSession = await dbContext.Sessions.SingleAsync(s => s.Id == otherActiveSession.Id);
        var refreshedRevokedSession = await dbContext.Sessions.SingleAsync(s => s.Id == alreadyRevokedSession.Id);

        Assert.Null(refreshedCurrentSession.RevokedAt);
        Assert.NotNull(refreshedOtherSession.RevokedAt);
        Assert.NotNull(refreshedRevokedSession.RevokedAt);
    }

    [Fact]
    public async Task ChangePasswordAsync_WhenCurrentSessionIdIsUnavailable_ThenRevokesAllActiveSessions()
    {
        await using var dbContext = CreateDbContext();
        var user = await SeedUserAsync(dbContext, "password-all@example.com", "OldPassword!1");

        var firstActive = await SeedSessionAsync(dbContext, user.Id, revoked: false);
        var secondActive = await SeedSessionAsync(dbContext, user.Id, revoked: false);

        var currentUser = new TestCurrentUserAccessor { UserId = user.Id };
        var sessionService = new TestSessionService();
        var challengeService = new TestAuthChallengeService();
        var userLookup = new TestUserLookupService(dbContext);

        var sut = new AccountService(
            dbContext,
            challengeService,
            sessionService,
            currentUser,
            userLookup,
            _passwordHasher,
            Options.Create(new AuthOptions()));

        var result = await sut.ChangePasswordAsync(
            new PasswordChangeRequest("OldPassword!1", "N3wPassword!2"),
            CancellationToken.None);

        Assert.Equal(ResultStatus.Ok, result.Status);

        var refreshedFirst = await dbContext.Sessions.SingleAsync(s => s.Id == firstActive.Id);
        var refreshedSecond = await dbContext.Sessions.SingleAsync(s => s.Id == secondActive.Id);

        Assert.NotNull(refreshedFirst.RevokedAt);
        Assert.NotNull(refreshedSecond.RevokedAt);
    }

    [Fact]
    public async Task ChangeEmailVerifyAsync_WhenPendingEmailDoesNotMatchChallengeTarget_ThenReturnsBadRequest()
    {
        await using var dbContext = CreateDbContext();
        var user = await SeedUserAsync(dbContext, "change-email-verify@example.com", "Password!1");
        user.PendingEmail = "pending@example.com";
        await dbContext.SaveChangesAsync();

        var challenge = BuildChallenge(user, ChallengePurpose.ChangeEmail, targetEmail: "other@example.com");

        var challengeService = new TestAuthChallengeService
        {
            NextGetActiveResult = Result<UserAuthChallenge>.Ok(challenge),
            NextVerifyResult = Result.Ok()
        };

        var sut = CreateSut(dbContext, challengeService, new TestCurrentUserAccessor { UserId = user.Id });

        var result = await sut.ChangeEmailVerifyAsync(
            new ChangeEmailVerifyRequest(challenge.Id, "123456"),
            CancellationToken.None);

        Assert.Equal(ResultStatus.BadRequest, result.Status);
        Assert.Equal(0, challengeService.VerifyCallCount);
        Assert.Equal("pending@example.com", user.PendingEmail);
    }

    [Fact]
    public async Task ChangeEmailCancelAsync_WhenPendingEmailDoesNotMatchChallengeTarget_ThenReturnsBadRequest()
    {
        await using var dbContext = CreateDbContext();
        var user = await SeedUserAsync(dbContext, "change-email-cancel@example.com", "Password!1");
        user.PendingEmail = "pending@example.com";
        await dbContext.SaveChangesAsync();

        var challenge = BuildChallenge(user, ChallengePurpose.ChangeEmail, targetEmail: "other@example.com");
        var originalExpiresAt = challenge.ExpiresAt;

        var challengeService = new TestAuthChallengeService
        {
            NextGetActiveResult = Result<UserAuthChallenge>.Ok(challenge)
        };

        var sut = CreateSut(dbContext, challengeService, new TestCurrentUserAccessor { UserId = user.Id });

        var result = await sut.ChangeEmailCancelAsync(
            new ChangeEmailCancelRequest(challenge.Id),
            CancellationToken.None);

        Assert.Equal(ResultStatus.BadRequest, result.Status);
        Assert.Equal("pending@example.com", user.PendingEmail);
        Assert.Equal(originalExpiresAt, challenge.ExpiresAt);
    }

    [Fact]
    public async Task ChangePhoneVerifyAsync_WhenPendingPhoneDoesNotMatchChallengeTarget_ThenReturnsBadRequest()
    {
        await using var dbContext = CreateDbContext();
        var user = await SeedUserAsync(dbContext, "change-phone-verify@example.com", "Password!1");
        user.PendingPhoneE164 = "+31611112222";
        await dbContext.SaveChangesAsync();

        var challenge = BuildChallenge(user, ChallengePurpose.ChangePhone, targetPhoneE164: "+31633334444");

        var challengeService = new TestAuthChallengeService
        {
            NextGetActiveResult = Result<UserAuthChallenge>.Ok(challenge),
            NextVerifyResult = Result.Ok()
        };

        var sut = CreateSut(dbContext, challengeService, new TestCurrentUserAccessor { UserId = user.Id });

        var result = await sut.ChangePhoneVerifyAsync(
            new ChangePhoneVerifyRequest(challenge.Id, "123456"),
            CancellationToken.None);

        Assert.Equal(ResultStatus.BadRequest, result.Status);
        Assert.Equal(0, challengeService.VerifyCallCount);
        Assert.Equal("+31611112222", user.PendingPhoneE164);
    }

    [Fact]
    public async Task ChangePhoneCancelAsync_WhenPendingPhoneDoesNotMatchChallengeTarget_ThenReturnsBadRequest()
    {
        await using var dbContext = CreateDbContext();
        var user = await SeedUserAsync(dbContext, "change-phone-cancel@example.com", "Password!1");
        user.PendingPhoneE164 = "+31611112222";
        await dbContext.SaveChangesAsync();

        var challenge = BuildChallenge(user, ChallengePurpose.ChangePhone, targetPhoneE164: "+31633334444");
        var originalExpiresAt = challenge.ExpiresAt;

        var challengeService = new TestAuthChallengeService
        {
            NextGetActiveResult = Result<UserAuthChallenge>.Ok(challenge)
        };

        var sut = CreateSut(dbContext, challengeService, new TestCurrentUserAccessor { UserId = user.Id });

        var result = await sut.ChangePhoneCancelAsync(
            new ChangePhoneCancelRequest(challenge.Id),
            CancellationToken.None);

        Assert.Equal(ResultStatus.BadRequest, result.Status);
        Assert.Equal("+31611112222", user.PendingPhoneE164);
        Assert.Equal(originalExpiresAt, challenge.ExpiresAt);
    }

    [Fact]
    public async Task GetMeAsync_WhenUserIsNotAuthenticated_ThenReturnsUnauthorized()
    {
        await using var dbContext = CreateDbContext();
        var sut = CreateSut(dbContext, new TestAuthChallengeService(), new TestCurrentUserAccessor());

        var result = await sut.GetMeAsync(CancellationToken.None);

        Assert.Equal(ResultStatus.Unauthorized, result.Status);
    }

    [Fact]
    public async Task GetMeAsync_WhenUserExists_ThenReturnsProfile()
    {
        await using var dbContext = CreateDbContext();
        var user = await SeedUserAsync(dbContext, "me@example.com", "Password!1");
        var dateOfBirth = new DateTime(1994, 5, 10);
        await SeedClientProfileAsync(dbContext, user.Id, dateOfBirth);

        var sut = CreateSut(
            dbContext,
            new TestAuthChallengeService(),
            new TestCurrentUserAccessor { UserId = user.Id });

        var result = await sut.GetMeAsync(CancellationToken.None);

        Assert.Equal(ResultStatus.Ok, result.Status);
        Assert.NotNull(result.Value);
        Assert.Equal(user.Name, result.Value!.Name);
        Assert.Equal(user.Email, result.Value.Email);
        Assert.Equal(user.PhoneE164, result.Value.PhoneE164);
        Assert.Equal(dateOfBirth.Date, result.Value.DateOfBirth);
    }

    [Fact]
    public async Task UpdateProfileAsync_WhenRequestHasNoChanges_ThenReturnsBadRequest()
    {
        await using var dbContext = CreateDbContext();
        var sut = CreateSut(dbContext, new TestAuthChallengeService(), new TestCurrentUserAccessor { UserId = Guid.NewGuid() });

        var result = await sut.UpdateProfileAsync(new UpdateProfileRequest(null, null), CancellationToken.None);

        Assert.Equal(ResultStatus.BadRequest, result.Status);
    }

    [Fact]
    public async Task UpdateProfileAsync_WhenNameAndDateOfBirthAreProvided_ThenPersistsChanges()
    {
        await using var dbContext = CreateDbContext();
        var user = await SeedUserAsync(dbContext, "profile@example.com", "Password!1");
        await SeedClientProfileAsync(dbContext, user.Id, new DateTime(1993, 3, 1));
        var newDateOfBirth = new DateTime(1992, 2, 2);
        const string newName = "Renamed User";

        var sut = CreateSut(
            dbContext,
            new TestAuthChallengeService(),
            new TestCurrentUserAccessor { UserId = user.Id });

        var result = await sut.UpdateProfileAsync(
            new UpdateProfileRequest(newName, newDateOfBirth),
            CancellationToken.None);

        Assert.Equal(ResultStatus.Ok, result.Status);

        var refreshedUser = await dbContext.Users.Include(u => u.ClientProfile).SingleAsync(u => u.Id == user.Id);
        Assert.Equal(newName, refreshedUser.Name);
        Assert.NotNull(refreshedUser.ClientProfile);
        Assert.Equal(newDateOfBirth.Date, refreshedUser.ClientProfile!.DateOfBirth);
    }

    [Fact]
    public async Task ChangeEmailAsync_WhenEmailIsAlreadyInUse_ThenReturnsConflict()
    {
        await using var dbContext = CreateDbContext();
        var currentUser = await SeedUserAsync(dbContext, "owner@example.com", "Password!1");
        await SeedUserAsync(dbContext, "used@example.com", "Password!1");

        var challengeService = new TestAuthChallengeService();
        var sut = CreateSut(
            dbContext,
            challengeService,
            new TestCurrentUserAccessor { UserId = currentUser.Id });

        var result = await sut.ChangeEmailAsync(new ChangeEmailRequest("  USED@EXAMPLE.COM "), CancellationToken.None);

        Assert.Equal(ResultStatus.Conflict, result.Status);
        Assert.Equal(0, challengeService.CreateCallCount);
    }

    [Fact]
    public async Task ChangeEmailAsync_WhenRequestIsValid_ThenSetsPendingEmailAndCreatesChallenge()
    {
        await using var dbContext = CreateDbContext();
        var user = await SeedUserAsync(dbContext, "owner@example.com", "Password!1");

        var challengeService = new TestAuthChallengeService();
        var sut = CreateSut(
            dbContext,
            challengeService,
            new TestCurrentUserAccessor { UserId = user.Id });

        var result = await sut.ChangeEmailAsync(new ChangeEmailRequest("  NEW@Example.com "), CancellationToken.None);

        Assert.Equal(ResultStatus.Ok, result.Status);
        Assert.NotNull(result.Value);
        Assert.Null(result.Value!.Code);
        Assert.Equal(1, challengeService.CreateCallCount);
        Assert.NotNull(challengeService.LastCreateRequest);
        Assert.Equal(ChallengePurpose.ChangeEmail, challengeService.LastCreateRequest!.Purpose);
        Assert.Equal(IdentifierNormalization.NormalizeEmail("  NEW@Example.com "), challengeService.LastCreateRequest.TargetEmail);

        Assert.Equal("new@example.com", user.PendingEmail);
        Assert.NotNull(user.PendingEmailRequestedAt);
    }

    [Fact]
    public async Task ChangePhoneAsync_WhenPhoneIsAlreadyInUse_ThenReturnsConflict()
    {
        await using var dbContext = CreateDbContext();
        var currentUser = await SeedUserAsync(dbContext, "owner@example.com", "Password!1");
        var inUsePhone = "+31699990000";
        var otherUser = await SeedUserAsync(dbContext, "other@example.com", "Password!1");
        otherUser.PhoneE164 = inUsePhone;
        await dbContext.SaveChangesAsync();

        var challengeService = new TestAuthChallengeService();
        var sut = CreateSut(
            dbContext,
            challengeService,
            new TestCurrentUserAccessor { UserId = currentUser.Id });

        var result = await sut.ChangePhoneAsync(new ChangePhoneRequest(inUsePhone), CancellationToken.None);

        Assert.Equal(ResultStatus.Conflict, result.Status);
        Assert.Equal(0, challengeService.CreateCallCount);
    }

    [Fact]
    public async Task ChangePhoneAsync_WhenRequestIsValid_ThenSetsPendingPhoneAndCreatesChallenge()
    {
        await using var dbContext = CreateDbContext();
        var user = await SeedUserAsync(dbContext, "owner@example.com", "Password!1");

        var challengeService = new TestAuthChallengeService();
        var sut = CreateSut(
            dbContext,
            challengeService,
            new TestCurrentUserAccessor { UserId = user.Id });

        var result = await sut.ChangePhoneAsync(new ChangePhoneRequest("00 31 6-7777-8888"), CancellationToken.None);

        Assert.Equal(ResultStatus.Ok, result.Status);
        Assert.NotNull(result.Value);
        Assert.Null(result.Value!.Code);
        Assert.Equal(1, challengeService.CreateCallCount);
        Assert.NotNull(challengeService.LastCreateRequest);
        Assert.Equal(ChallengePurpose.ChangePhone, challengeService.LastCreateRequest!.Purpose);
        Assert.Equal("+31677778888", challengeService.LastCreateRequest.TargetPhoneE164);

        Assert.Equal("+31677778888", user.PendingPhoneE164);
        Assert.NotNull(user.PendingPhoneRequestedAt);
    }

    [Fact]
    public async Task ChangeEmailAsync_WhenDebugCodesEnabled_ThenReturnsCode()
    {
        await using var dbContext = CreateDbContext();
        var user = await SeedUserAsync(dbContext, "owner@example.com", "Password!1");

        var challengeService = new TestAuthChallengeService
        {
            NextCreateResult = new AuthChallengeCreation(Guid.NewGuid(), "123456")
        };
        var sut = CreateSut(
            dbContext,
            challengeService,
            new TestCurrentUserAccessor { UserId = user.Id },
            returnDebugCodes: true);

        var result = await sut.ChangeEmailAsync(new ChangeEmailRequest("new@example.com"), CancellationToken.None);

        Assert.Equal(ResultStatus.Ok, result.Status);
        Assert.NotNull(result.Value);
        Assert.Equal("123456", result.Value!.Code);
    }

    [Fact]
    public async Task ChangePhoneAsync_WhenDebugCodesEnabled_ThenReturnsCode()
    {
        await using var dbContext = CreateDbContext();
        var user = await SeedUserAsync(dbContext, "owner@example.com", "Password!1");

        var challengeService = new TestAuthChallengeService
        {
            NextCreateResult = new AuthChallengeCreation(Guid.NewGuid(), "654321")
        };
        var sut = CreateSut(
            dbContext,
            challengeService,
            new TestCurrentUserAccessor { UserId = user.Id },
            returnDebugCodes: true);

        var result = await sut.ChangePhoneAsync(new ChangePhoneRequest("+31677778888"), CancellationToken.None);

        Assert.Equal(ResultStatus.Ok, result.Status);
        Assert.NotNull(result.Value);
        Assert.Equal("654321", result.Value!.Code);
    }

    [Fact]
    public async Task GetSessionsAsync_WhenUserIsNotAuthenticated_ThenReturnsUnauthorized()
    {
        await using var dbContext = CreateDbContext();
        var sut = CreateSut(dbContext, new TestAuthChallengeService(), new TestCurrentUserAccessor());

        var result = await sut.GetSessionsAsync(CancellationToken.None);

        Assert.Equal(ResultStatus.Unauthorized, result.Status);
    }

    [Fact]
    public async Task GetSessionsAsync_WhenUserHasActiveSessions_ThenReturnsOnlyActiveSessionsAndLatestLogin()
    {
        await using var dbContext = CreateDbContext();
        var user = await SeedUserAsync(dbContext, "sessions@example.com", "Password!1");
        var otherUser = await SeedUserAsync(dbContext, "other-sessions@example.com", "Password!1");

        var olderSession = await SeedSessionAsync(dbContext, user.Id, revoked: false);
        var latestSession = await SeedSessionAsync(dbContext, user.Id, revoked: false);
        _ = await SeedSessionAsync(dbContext, user.Id, revoked: true);
        _ = await SeedSessionAsync(dbContext, otherUser.Id, revoked: false);

        var olderCreatedAt = new DateTime(2025, 1, 1, 9, 0, 0, DateTimeKind.Utc);
        var latestCreatedAt = new DateTime(2025, 1, 2, 10, 0, 0, DateTimeKind.Utc);
        olderSession.CreatedAt = olderCreatedAt;
        olderSession.UserAgent = "older-agent";
        olderSession.IpAddress = "10.0.0.1";
        latestSession.CreatedAt = latestCreatedAt;
        latestSession.UserAgent = "latest-agent";
        latestSession.IpAddress = "10.0.0.2";
        await dbContext.SaveChangesAsync();

        var sut = CreateSut(
            dbContext,
            new TestAuthChallengeService(),
            new TestCurrentUserAccessor { UserId = user.Id });

        var result = await sut.GetSessionsAsync(CancellationToken.None);

        Assert.Equal(ResultStatus.Ok, result.Status);
        Assert.NotNull(result.Value);
        Assert.Equal(2, result.Value!.Sessions.Count);
        Assert.Equal(latestCreatedAt, result.Value.LastLoginAt);
        Assert.Equal("latest-agent", result.Value.LastLoginUserAgent);
        Assert.Equal("10.0.0.2", result.Value.LastLoginIpAddress);
    }

    [Fact]
    public async Task LogoutAsync_WhenSessionExists_ThenRevokesSessionAndClearsCookie()
    {
        await using var dbContext = CreateDbContext();
        var user = await SeedUserAsync(dbContext, "logout@example.com", "Password!1");
        var session = await SeedSessionAsync(dbContext, user.Id, revoked: false);

        var sessionService = new TestSessionService();
        var sut = CreateSut(
            dbContext,
            new TestAuthChallengeService(),
            new TestCurrentUserAccessor { SessionId = session.Id, UserId = user.Id },
            sessionService);

        var result = await sut.LogoutAsync(CancellationToken.None);

        Assert.Equal(ResultStatus.Ok, result.Status);
        Assert.Equal(1, sessionService.ClearCookieCallCount);

        var refreshedSession = await dbContext.Sessions.SingleAsync(s => s.Id == session.Id);
        Assert.NotNull(refreshedSession.RevokedAt);
    }

    [Fact]
    public async Task LogoutAsync_WhenSessionDoesNotExist_ThenStillClearsCookie()
    {
        await using var dbContext = CreateDbContext();

        var sessionService = new TestSessionService();
        var sut = CreateSut(
            dbContext,
            new TestAuthChallengeService(),
            new TestCurrentUserAccessor { SessionId = Guid.NewGuid(), UserId = Guid.NewGuid() },
            sessionService);

        var result = await sut.LogoutAsync(CancellationToken.None);

        Assert.Equal(ResultStatus.Ok, result.Status);
        Assert.Equal(1, sessionService.ClearCookieCallCount);
    }

    [Fact]
    public async Task LogoutAllAsync_WhenUserIsAuthenticated_ThenRevokesOwnActiveSessionsAndClearsCookie()
    {
        await using var dbContext = CreateDbContext();
        var user = await SeedUserAsync(dbContext, "logout-all@example.com", "Password!1");
        var anotherUser = await SeedUserAsync(dbContext, "other@example.com", "Password!1");

        var firstActive = await SeedSessionAsync(dbContext, user.Id, revoked: false);
        var secondActive = await SeedSessionAsync(dbContext, user.Id, revoked: false);
        var alreadyRevoked = await SeedSessionAsync(dbContext, user.Id, revoked: true);
        var otherUserActive = await SeedSessionAsync(dbContext, anotherUser.Id, revoked: false);

        var sessionService = new TestSessionService();
        var sut = CreateSut(
            dbContext,
            new TestAuthChallengeService(),
            new TestCurrentUserAccessor { UserId = user.Id },
            sessionService);

        var result = await sut.LogoutAllAsync(CancellationToken.None);

        Assert.Equal(ResultStatus.Ok, result.Status);
        Assert.Equal(1, sessionService.ClearCookieCallCount);

        var refreshedFirst = await dbContext.Sessions.SingleAsync(s => s.Id == firstActive.Id);
        var refreshedSecond = await dbContext.Sessions.SingleAsync(s => s.Id == secondActive.Id);
        var refreshedAlreadyRevoked = await dbContext.Sessions.SingleAsync(s => s.Id == alreadyRevoked.Id);
        var refreshedOther = await dbContext.Sessions.SingleAsync(s => s.Id == otherUserActive.Id);

        Assert.NotNull(refreshedFirst.RevokedAt);
        Assert.NotNull(refreshedSecond.RevokedAt);
        Assert.NotNull(refreshedAlreadyRevoked.RevokedAt);
        Assert.Null(refreshedOther.RevokedAt);
    }

    private AccountService CreateSut(
        AppDbContext dbContext,
        TestAuthChallengeService challengeService,
        TestCurrentUserAccessor currentUserAccessor,
        TestSessionService? sessionService = null,
        bool returnDebugCodes = false)
    {
        return new AccountService(
            dbContext,
            challengeService,
            sessionService ?? new TestSessionService(),
            currentUserAccessor,
            new TestUserLookupService(dbContext),
            _passwordHasher,
            Options.Create(new AuthOptions
            {
                ReturnDebugCodes = returnDebugCodes
            }));
    }

    private async Task<User> SeedUserAsync(AppDbContext dbContext, string email, string password, bool mustChangePassword = false)
    {
        var now = DateTime.UtcNow;
        var user = new User
        {
            Id = Guid.NewGuid(),
            Name = "account-user",
            Email = email,
            PhoneE164 = "+31612345678",
            PasswordHash = string.Empty,
            Role = "client",
            MustChangePassword = mustChangePassword,
            IsVerified = true,
            IsActive = true,
            CreatedAt = now,
            UpdatedAt = now
        };

        user.PasswordHash = _passwordHasher.HashPassword(user, password);

        dbContext.Users.Add(user);
        await dbContext.SaveChangesAsync();
        return user;
    }

    private static async Task SeedClientProfileAsync(AppDbContext dbContext, Guid userId, DateTime dateOfBirth)
    {
        var client = new Client
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            TherapistUserId = Guid.NewGuid(),
            DateOfBirth = dateOfBirth.Date,
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow
        };

        dbContext.Clients.Add(client);
        await dbContext.SaveChangesAsync();
    }

    private static async Task<Session> SeedSessionAsync(AppDbContext dbContext, Guid userId, bool revoked)
    {
        var now = DateTime.UtcNow;
        var session = new Session
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            SessionTokenHash = Guid.NewGuid().ToByteArray(),
            UserAgent = "xunit",
            IpAddress = "127.0.0.1",
            CreatedAt = now,
            LastSeenAt = now,
            ExpiresAt = now.AddDays(14),
            RevokedAt = revoked ? now : null
        };

        dbContext.Sessions.Add(session);
        await dbContext.SaveChangesAsync();
        return session;
    }

    private static UserAuthChallenge BuildChallenge(
        User user,
        ChallengePurpose purpose,
        string? targetEmail = null,
        string? targetPhoneE164 = null)
    {
        return new UserAuthChallenge
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            User = user,
            Purpose = purpose.ToValue(),
            TargetEmail = targetEmail,
            TargetPhoneE164 = targetPhoneE164,
            CodeHash = [1, 2, 3],
            AttemptCount = 0,
            ResendCount = 0,
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.AddMinutes(5)
        };
    }

    private static AppDbContext CreateDbContext()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseInMemoryDatabase($"account-service-tests-{Guid.NewGuid():N}")
            .Options;

        var dbContext = new AppDbContext(options);
        dbContext.Database.EnsureCreated();
        return dbContext;
    }

    private sealed class TestSessionService : ISessionService
    {
        public int ClearCookieCallCount { get; private set; }

        public Task CreateSessionAndSetCookieAsync(User user, DateTime now, CancellationToken cancellationToken)
            => Task.CompletedTask;

        public void ClearSessionCookie()
        {
            ClearCookieCallCount += 1;
        }
    }

    private sealed class TestCurrentUserAccessor : ICurrentUserAccessor
    {
        public Guid? UserId { get; init; }
        public Guid? SessionId { get; init; }

        public bool TryGetUserId(out Guid userId)
        {
            if (UserId.HasValue)
            {
                userId = UserId.Value;
                return true;
            }

            userId = Guid.Empty;
            return false;
        }

        public bool TryGetSessionId(out Guid sessionId)
        {
            if (SessionId.HasValue)
            {
                sessionId = SessionId.Value;
                return true;
            }

            sessionId = Guid.Empty;
            return false;
        }

        public bool TryGetRole(out string? role)
        {
            role = null;
            return false;
        }
    }

    private sealed class TestUserLookupService(AppDbContext dbContext) : IUserLookupService
    {
        private readonly AppDbContext _dbContext = dbContext;

        public Task<User?> GetActiveUserAsync(Guid userId, UserTrackingMode trackingMode, CancellationToken cancellationToken)
            => GetUserAsync(userId, trackingMode, includeClientProfile: false, cancellationToken);

        public Task<User?> GetActiveUserWithClientProfileAsync(
            Guid userId,
            UserTrackingMode trackingMode,
            CancellationToken cancellationToken)
            => GetUserAsync(userId, trackingMode, includeClientProfile: true, cancellationToken);

        private async Task<User?> GetUserAsync(
            Guid userId,
            UserTrackingMode trackingMode,
            bool includeClientProfile,
            CancellationToken cancellationToken)
        {
            IQueryable<User> query = _dbContext.Users.Where(u => u.Id == userId && u.IsActive);

            if (includeClientProfile)
                query = query.Include(u => u.ClientProfile);

            if (trackingMode == UserTrackingMode.ReadOnly)
                query = query.AsNoTracking();

            return await query.FirstOrDefaultAsync(cancellationToken);
        }
    }

    private sealed class TestAuthChallengeService : IAuthChallengeService
    {
        public int CreateCallCount { get; private set; }
        public int VerifyCallCount { get; private set; }
        public AuthChallengeRequest? LastCreateRequest { get; private set; }

        public AuthChallengeCreation NextCreateResult { get; set; } = new(Guid.NewGuid(), "123456");
        public Result<UserAuthChallenge> NextGetActiveResult { get; set; } = Result<UserAuthChallenge>.Unauthorized();
        public Result NextVerifyResult { get; set; } = Result.Unauthorized();

        public Task<AuthChallengeCreation> CreateChallengeAsync(
            AuthChallengeRequest request,
            DateTime now,
            CancellationToken cancellationToken)
        {
            CreateCallCount += 1;
            LastCreateRequest = request;
            return Task.FromResult(NextCreateResult);
        }

        public Task<Result<UserAuthChallenge>> GetActiveChallengeAsync(
            Guid challengeId,
            ChallengePurpose purpose,
            Guid? userId,
            DateTime now,
            CancellationToken cancellationToken)
            => Task.FromResult(NextGetActiveResult);

        public Task<Result> VerifyChallengeCodeAsync(
            UserAuthChallenge challenge,
            string code,
            DateTime now,
            CancellationToken cancellationToken)
        {
            VerifyCallCount += 1;
            return Task.FromResult(NextVerifyResult);
        }

        public Task<Result<AuthChallengeResendResult>> ResendChallengeAsync(
            Guid challengeId,
            Guid? requesterUserId,
            DateTime now,
            CancellationToken cancellationToken)
            => Task.FromResult(Result<AuthChallengeResendResult>.TooManyRequests());
    }
}
