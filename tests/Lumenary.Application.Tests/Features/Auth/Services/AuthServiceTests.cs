using Lumenary.Features.Auth.Challenges;
using Lumenary.Infrastructure.Identity;
using Lumenary.Application.Common.Options;
using Lumenary.Persistence;
using Lumenary.Domain.ValueObjects;
using Lumenary.Features.Auth.Models;
using Lumenary.Persistence.Entities;
using Lumenary.Features.Auth.Services;
using Lumenary.Common.Results;
using Lumenary.Features.Auth.Users;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Lumenary.Tests.Features.Auth.Services;

public sealed class AuthServiceTests(AuthServiceFixture fixture) : IClassFixture<AuthServiceFixture>
{
    [Fact]
    public async Task LoginAsync_WhenUserMissing_ThenReturnsGenericOkWithoutCreatingChallenge()
    {
        await using var dbContext = fixture.CreateDbContext();
        var challengeService = new FakeAuthChallengeService(dbContext);
        var sessionService = new FakeSessionService();
        var currentUserAccessor = new FakeCurrentUserAccessor();
        var sut = fixture.CreateSut(dbContext, challengeService, sessionService, currentUserAccessor,
            returnDebugCodes: false);

        var result = await sut.LoginAsync(new LoginRequest("missing@example.com", "AnyPassword123!"),
            CancellationToken.None);

        Assert.Equal(ResultStatus.Ok, result.Status);
        Assert.NotNull(result.Value);
        Assert.NotEqual(Guid.Empty, result.Value!.ChallengeId);
        Assert.Null(result.Value.Code);
        Assert.Equal(0, challengeService.CreateCallCount);
    }

    [Fact]
    public async Task LoginAsync_WhenCredentialsAreValid_ThenCreatesLoginChallenge()
    {
        await using var dbContext = fixture.CreateDbContext();
        var user = await fixture.SeedUserAsync(
            dbContext,
            UserRoles.Client,
            "client@example.com",
            "+31612345678",
            "Str0ng!Pass1");

        var challengeService = new FakeAuthChallengeService(dbContext)
        {
            NextCreateResult = new AuthChallengeCreation(Guid.NewGuid(), "654321")
        };
        var sessionService = new FakeSessionService();
        var currentUserAccessor = new FakeCurrentUserAccessor();
        var sut = fixture.CreateSut(dbContext, challengeService, sessionService, currentUserAccessor,
            returnDebugCodes: true);

        var result = await sut.LoginAsync(new LoginRequest("  CLIENT@EXAMPLE.COM ", "Str0ng!Pass1"),
            CancellationToken.None);

        Assert.Equal(ResultStatus.Ok, result.Status);
        Assert.NotNull(result.Value);
        Assert.Equal(challengeService.NextCreateResult.ChallengeId, result.Value!.ChallengeId);
        Assert.Equal("654321", result.Value.Code);

        Assert.Equal(1, challengeService.CreateCallCount);
        Assert.NotNull(challengeService.LastCreateRequest);
        Assert.Equal(user.Id, challengeService.LastCreateRequest!.UserId);
        Assert.Equal(ChallengePurpose.Login, challengeService.LastCreateRequest.Purpose);
        Assert.Equal(user.PhoneE164, challengeService.LastCreateRequest.TargetPhoneE164);
        Assert.Null(challengeService.LastCreateRequest.TargetEmail);
    }

    [Fact]
    public async Task LoginAsync_WhenUserIsInactive_ThenReturnsGenericOkWithoutCreatingChallenge()
    {
        await using var dbContext = fixture.CreateDbContext();
        await fixture.SeedUserAsync(
            dbContext,
            UserRoles.Client,
            "inactive@example.com",
            "+31610001111",
            "Str0ng!Pass1",
            isActive: false);

        var challengeService = new FakeAuthChallengeService(dbContext);
        var sessionService = new FakeSessionService();
        var currentUserAccessor = new FakeCurrentUserAccessor();
        var sut = fixture.CreateSut(dbContext, challengeService, sessionService, currentUserAccessor,
            returnDebugCodes: false);

        var result = await sut.LoginAsync(new LoginRequest("inactive@example.com", "Str0ng!Pass1"),
            CancellationToken.None);

        Assert.Equal(ResultStatus.Ok, result.Status);
        Assert.NotNull(result.Value);
        Assert.NotEqual(Guid.Empty, result.Value!.ChallengeId);
        Assert.Null(result.Value.Code);
        Assert.Equal(0, challengeService.CreateCallCount);
    }

    [Fact]
    public async Task LoginAsync_WhenPasswordIsInvalid_ThenReturnsGenericOkWithoutCreatingChallenge()
    {
        await using var dbContext = fixture.CreateDbContext();
        await fixture.SeedUserAsync(
            dbContext,
            UserRoles.Client,
            "invalidpassword@example.com",
            "+31610002222",
            "Str0ng!Pass1");

        var challengeService = new FakeAuthChallengeService(dbContext);
        var sessionService = new FakeSessionService();
        var currentUserAccessor = new FakeCurrentUserAccessor();
        var sut = fixture.CreateSut(dbContext, challengeService, sessionService, currentUserAccessor,
            returnDebugCodes: false);

        var result = await sut.LoginAsync(new LoginRequest("invalidpassword@example.com", "WrongPassword!1"),
            CancellationToken.None);

        Assert.Equal(ResultStatus.Ok, result.Status);
        Assert.NotNull(result.Value);
        Assert.NotEqual(Guid.Empty, result.Value!.ChallengeId);
        Assert.Null(result.Value.Code);
        Assert.Equal(0, challengeService.CreateCallCount);
    }

    [Fact]
    public async Task LoginVerifyAsync_WhenChallengeIsInvalid_ThenReturnsUnauthorized()
    {
        await using var dbContext = fixture.CreateDbContext();
        var challengeService = new FakeAuthChallengeService(dbContext)
        {
            NextGetActiveResult = Result<UserAuthChallenge>.Unauthorized()
        };
        var sessionService = new FakeSessionService();
        var currentUserAccessor = new FakeCurrentUserAccessor();
        var sut = fixture.CreateSut(dbContext, challengeService, sessionService, currentUserAccessor,
            returnDebugCodes: false);

        var result = await sut.LoginVerifyAsync(new LoginVerifyRequest(Guid.NewGuid(), "123456"), CancellationToken.None);

        Assert.Equal(ResultStatus.Unauthorized, result.Status);
        Assert.Equal(0, challengeService.VerifyCallCount);
        Assert.Equal(0, sessionService.CreateCallCount);
    }

    [Fact]
    public async Task LoginVerifyAsync_WhenCodeIsValid_ThenCreatesSessionAndReturnsOk()
    {
        await using var dbContext = fixture.CreateDbContext();
        var user = await fixture.SeedUserAsync(
            dbContext,
            UserRoles.Client,
            "loginverify@example.com",
            "+31611112222",
            "Str0ng!Pass2");

        var challenge = fixture.BuildTransientChallenge(user, ChallengePurpose.Login, "+31611112222");
        var challengeService = new FakeAuthChallengeService(dbContext)
        {
            NextGetActiveResult = Result<UserAuthChallenge>.Ok(challenge),
            NextVerifyResult = Result.Ok()
        };
        var sessionService = new FakeSessionService();
        var currentUserAccessor = new FakeCurrentUserAccessor();
        var sut = fixture.CreateSut(dbContext, challengeService, sessionService, currentUserAccessor,
            returnDebugCodes: false);

        var result = await sut.LoginVerifyAsync(new LoginVerifyRequest(challenge.Id, "222222"), CancellationToken.None);

        Assert.Equal(ResultStatus.Ok, result.Status);
        Assert.Equal(1, challengeService.VerifyCallCount);
        Assert.Equal(1, sessionService.CreateCallCount);
        Assert.Equal(user.Id, sessionService.LastCreatedUserId);
    }

    [Fact]
    public async Task LoginVerifyAsync_WhenVerificationFails_ThenReturnsFailureWithoutCreatingSession()
    {
        await using var dbContext = fixture.CreateDbContext();
        var user = await fixture.SeedUserAsync(
            dbContext,
            UserRoles.Client,
            "loginverify-fail@example.com",
            "+31610003333",
            "Str0ng!Pass1");

        var challenge = fixture.BuildTransientChallenge(user, ChallengePurpose.Login, user.PhoneE164);
        var challengeService = new FakeAuthChallengeService(dbContext)
        {
            NextGetActiveResult = Result<UserAuthChallenge>.Ok(challenge),
            NextVerifyResult = Result.TooManyRequests()
        };
        var sessionService = new FakeSessionService();
        var currentUserAccessor = new FakeCurrentUserAccessor();
        var sut = fixture.CreateSut(dbContext, challengeService, sessionService, currentUserAccessor,
            returnDebugCodes: false);

        var result = await sut.LoginVerifyAsync(new LoginVerifyRequest(challenge.Id, "123456"), CancellationToken.None);

        Assert.Equal(ResultStatus.TooManyRequests, result.Status);
        Assert.Equal(1, challengeService.VerifyCallCount);
        Assert.Equal(0, sessionService.CreateCallCount);
    }

    [Fact]
    public async Task RegisterAsync_WhenEmailOrPhoneAlreadyExists_ThenReturnsGenericOkWithoutChallengeCreation()
    {
        await using var dbContext = fixture.CreateDbContext();
        await fixture.SeedUserAsync(dbContext, UserRoles.Client, "existing@example.com", "+31620000001", "Str0ng!Pass3");

        var challengeService = new FakeAuthChallengeService(dbContext);
        var sessionService = new FakeSessionService();
        var currentUserAccessor = new FakeCurrentUserAccessor();
        var sut = fixture.CreateSut(dbContext, challengeService, sessionService, currentUserAccessor,
            returnDebugCodes: false);

        var request = new RegisterRequest(
            "Test User",
            "existing@example.com",
            "Str0ng!Pass9",
            "+31699998888",
            new DateTime(1995, 1, 1));

        var result = await sut.RegisterAsync(request, CancellationToken.None);

        Assert.Equal(ResultStatus.Ok, result.Status);
        Assert.NotNull(result.Value);
        Assert.Equal(0, challengeService.CreateCallCount);
        Assert.Null(result.Value!.Code);
    }

    [Fact]
    public async Task RegisterAsync_WhenNoActiveTherapistExists_ThenReturnsServiceUnavailable()
    {
        await using var dbContext = fixture.CreateDbContext();
        var challengeService = new FakeAuthChallengeService(dbContext);
        var sessionService = new FakeSessionService();
        var currentUserAccessor = new FakeCurrentUserAccessor();
        var sut = fixture.CreateSut(dbContext, challengeService, sessionService, currentUserAccessor,
            returnDebugCodes: false);

        var request = new RegisterRequest(
            "New Client",
            "newclient@example.com",
            "Str0ng!Pass4",
            "+31644445555",
            new DateTime(1998, 4, 12));

        var result = await sut.RegisterAsync(request, CancellationToken.None);

        Assert.Equal(ResultStatus.ServiceUnavailable, result.Status);
        Assert.Equal(0, challengeService.CreateCallCount);
    }

    [Fact]
    public async Task RegisterAsync_WhenRequestIsValid_ThenCreatesClientUserAndChallenge()
    {
        await using var dbContext = fixture.CreateDbContext();
        var therapist = await fixture.SeedUserAsync(
            dbContext,
            UserRoles.Therapist,
            "therapist@example.com",
            "+31630000000",
            "Str0ng!Pass5");

        var challengeService = new FakeAuthChallengeService(dbContext)
        {
            NextCreateResult = new AuthChallengeCreation(Guid.NewGuid(), "123123")
        };
        var sessionService = new FakeSessionService();
        var currentUserAccessor = new FakeCurrentUserAccessor();
        var sut = fixture.CreateSut(dbContext, challengeService, sessionService, currentUserAccessor,
            returnDebugCodes: true);

        var request = new RegisterRequest(
            "Fresh Client",
            "  FRESH.CLIENT@Example.com ",
            "Str0ng!Pass6",
            "00 31 6-1212-3434",
            new DateTime(2001, 7, 23));

        var result = await sut.RegisterAsync(request, CancellationToken.None);

        Assert.Equal(ResultStatus.Ok, result.Status);
        Assert.NotNull(result.Value);
        Assert.Equal(challengeService.NextCreateResult.ChallengeId, result.Value!.ChallengeId);
        Assert.Equal("123123", result.Value.Code);

        var normalizedEmail = IdentifierNormalization.NormalizeEmail(request.Email);
        var normalizedPhone = IdentifierNormalization.NormalizePhoneE164(request.PhoneE164);

        var createdUser = await dbContext.Users.SingleAsync(u => u.Email == normalizedEmail);
        Assert.Equal(UserRoles.Client, createdUser.Role);
        Assert.True(createdUser.IsActive);
        Assert.False(createdUser.IsVerified);
        Assert.Equal(normalizedPhone, createdUser.PhoneE164);

        var passwordResult = fixture.PasswordHasher.VerifyHashedPassword(createdUser, createdUser.PasswordHash, request.Password);
        Assert.NotEqual(PasswordVerificationResult.Failed, passwordResult);

        var createdClient = await dbContext.Clients.SingleAsync(c => c.UserId == createdUser.Id);
        Assert.Equal(therapist.Id, createdClient.TherapistUserId);

        Assert.Equal(1, challengeService.CreateCallCount);
        Assert.NotNull(challengeService.LastCreateRequest);
        Assert.Equal(createdUser.Id, challengeService.LastCreateRequest!.UserId);
        Assert.Equal(ChallengePurpose.Register, challengeService.LastCreateRequest.Purpose);
        Assert.Equal(normalizedPhone, challengeService.LastCreateRequest.TargetPhoneE164);
    }

    [Fact]
    public async Task RegisterAsync_WhenChallengeServiceDoesNotSaveChanges_ThenPersistsUserAndClientWithinServiceBoundary()
    {
        await using var dbContext = fixture.CreateDbContext();
        _ = await fixture.SeedUserAsync(
            dbContext,
            UserRoles.Therapist,
            "therapist-nopersist@example.com",
            "+31630000111",
            "Str0ng!Pass5");

        var challengeService = new FakeAuthChallengeService(dbContext)
        {
            SaveChangesOnCreate = false
        };
        var sessionService = new FakeSessionService();
        var currentUserAccessor = new FakeCurrentUserAccessor();
        var sut = fixture.CreateSut(dbContext, challengeService, sessionService, currentUserAccessor,
            returnDebugCodes: false);

        var request = new RegisterRequest(
            "No Persist Client",
            "nopersist@example.com",
            "Str0ng!Pass6",
            "+31670000000",
            new DateTime(2002, 8, 24));

        var result = await sut.RegisterAsync(request, CancellationToken.None);

        Assert.Equal(ResultStatus.Ok, result.Status);
        Assert.DoesNotContain(
            dbContext.ChangeTracker.Entries(),
            entry => entry.State is EntityState.Added or EntityState.Modified);
    }

    [Fact]
    public async Task RegisterVerifyAsync_WhenChallengeIsInvalid_ThenReturnsUnauthorized()
    {
        await using var dbContext = fixture.CreateDbContext();
        var challengeService = new FakeAuthChallengeService(dbContext)
        {
            NextGetActiveResult = Result<UserAuthChallenge>.Unauthorized()
        };
        var sessionService = new FakeSessionService();
        var currentUserAccessor = new FakeCurrentUserAccessor();
        var sut = fixture.CreateSut(dbContext, challengeService, sessionService, currentUserAccessor,
            returnDebugCodes: false);

        var result = await sut.RegisterVerifyAsync(new RegisterVerifyRequest(Guid.NewGuid(), "222222"), CancellationToken.None);

        Assert.Equal(ResultStatus.Unauthorized, result.Status);
        Assert.Equal(0, sessionService.CreateCallCount);
    }

    [Fact]
    public async Task RegisterVerifyAsync_WhenCodeIsValid_ThenMarksUserVerifiedAndCreatesSession()
    {
        await using var dbContext = fixture.CreateDbContext();
        var user = await fixture.SeedUserAsync(
            dbContext,
            UserRoles.Client,
            "registerverify@example.com",
            "+31622223333",
            "Str0ng!Pass7",
            isVerified: false);

        var challenge = fixture.BuildTransientChallenge(user, ChallengePurpose.Register, user.PhoneE164);
        var challengeService = new FakeAuthChallengeService(dbContext)
        {
            NextGetActiveResult = Result<UserAuthChallenge>.Ok(challenge),
            NextVerifyResult = Result.Ok()
        };
        var sessionService = new FakeSessionService();
        var currentUserAccessor = new FakeCurrentUserAccessor();
        var sut = fixture.CreateSut(dbContext, challengeService, sessionService, currentUserAccessor,
            returnDebugCodes: false);

        var result = await sut.RegisterVerifyAsync(new RegisterVerifyRequest(challenge.Id, "333333"), CancellationToken.None);

        Assert.Equal(ResultStatus.Ok, result.Status);
        Assert.True(user.IsVerified);
        Assert.Equal(1, sessionService.CreateCallCount);
        Assert.Equal(user.Id, sessionService.LastCreatedUserId);
    }

    [Fact]
    public async Task RegisterVerifyAsync_WhenVerificationFails_ThenReturnsFailureWithoutMutatingUser()
    {
        await using var dbContext = fixture.CreateDbContext();
        var user = await fixture.SeedUserAsync(
            dbContext,
            UserRoles.Client,
            "registerverify-fail@example.com",
            "+31610004444",
            "Str0ng!Pass1",
            isVerified: false);

        var challenge = fixture.BuildTransientChallenge(user, ChallengePurpose.Register, user.PhoneE164);
        var challengeService = new FakeAuthChallengeService(dbContext)
        {
            NextGetActiveResult = Result<UserAuthChallenge>.Ok(challenge),
            NextVerifyResult = Result.Unauthorized()
        };
        var sessionService = new FakeSessionService();
        var currentUserAccessor = new FakeCurrentUserAccessor();
        var sut = fixture.CreateSut(dbContext, challengeService, sessionService, currentUserAccessor,
            returnDebugCodes: false);

        var result = await sut.RegisterVerifyAsync(new RegisterVerifyRequest(challenge.Id, "123456"), CancellationToken.None);

        Assert.Equal(ResultStatus.Unauthorized, result.Status);
        Assert.False(user.IsVerified);
        Assert.Equal(1, challengeService.VerifyCallCount);
        Assert.Equal(0, sessionService.CreateCallCount);
    }

    [Fact]
    public async Task PasswordResetAsync_WhenUserIsMissing_ThenReturnsGenericOkWithoutChallengeCreation()
    {
        await using var dbContext = fixture.CreateDbContext();
        var challengeService = new FakeAuthChallengeService(dbContext);
        var sessionService = new FakeSessionService();
        var currentUserAccessor = new FakeCurrentUserAccessor();
        var sut = fixture.CreateSut(dbContext, challengeService, sessionService, currentUserAccessor,
            returnDebugCodes: false);

        var result = await sut.PasswordResetAsync(new PasswordResetRequest("missing@example.com"), CancellationToken.None);

        Assert.Equal(ResultStatus.Ok, result.Status);
        Assert.NotNull(result.Value);
        Assert.NotEqual(Guid.Empty, result.Value!.ChallengeId);
        Assert.Null(result.Value.Code);
        Assert.Equal(0, challengeService.CreateCallCount);
    }

    [Fact]
    public async Task PasswordResetAsync_WhenUserExists_ThenCreatesPasswordResetChallenge()
    {
        await using var dbContext = fixture.CreateDbContext();
        var user = await fixture.SeedUserAsync(
            dbContext,
            UserRoles.Client,
            "pwdreset@example.com",
            "+31655556666",
            "Str0ng!Pass8");

        var challengeService = new FakeAuthChallengeService(dbContext)
        {
            NextCreateResult = new AuthChallengeCreation(Guid.NewGuid(), "444444")
        };
        var sessionService = new FakeSessionService();
        var currentUserAccessor = new FakeCurrentUserAccessor();
        var sut = fixture.CreateSut(dbContext, challengeService, sessionService, currentUserAccessor,
            returnDebugCodes: false);

        var result = await sut.PasswordResetAsync(new PasswordResetRequest(" PWDRESET@EXAMPLE.COM "), CancellationToken.None);

        Assert.Equal(ResultStatus.Ok, result.Status);
        Assert.NotNull(result.Value);
        Assert.Equal(challengeService.NextCreateResult.ChallengeId, result.Value!.ChallengeId);
        Assert.Null(result.Value.Code);
        Assert.Equal(1, challengeService.CreateCallCount);
        Assert.NotNull(challengeService.LastCreateRequest);
        Assert.Equal(user.Id, challengeService.LastCreateRequest!.UserId);
        Assert.Equal(ChallengePurpose.PasswordReset, challengeService.LastCreateRequest.Purpose);
        Assert.Equal(user.PhoneE164, challengeService.LastCreateRequest.TargetPhoneE164);
    }

    [Fact]
    public async Task PasswordResetAsync_WhenDebugCodesEnabledAndUserExists_ThenReturnsChallengeCode()
    {
        await using var dbContext = fixture.CreateDbContext();
        await fixture.SeedUserAsync(
            dbContext,
            UserRoles.Client,
            "pwdreset-debug@example.com",
            "+31655557777",
            "Str0ng!Pass8");

        var challengeService = new FakeAuthChallengeService(dbContext)
        {
            NextCreateResult = new AuthChallengeCreation(Guid.NewGuid(), "121212")
        };
        var sessionService = new FakeSessionService();
        var currentUserAccessor = new FakeCurrentUserAccessor();
        var sut = fixture.CreateSut(dbContext, challengeService, sessionService, currentUserAccessor,
            returnDebugCodes: true);

        var result = await sut.PasswordResetAsync(
            new PasswordResetRequest("pwdreset-debug@example.com"),
            CancellationToken.None);

        Assert.Equal(ResultStatus.Ok, result.Status);
        Assert.NotNull(result.Value);
        Assert.Equal("121212", result.Value!.Code);
    }

    [Fact]
    public async Task PasswordResetAsync_WhenDebugCodesEnabledAndUserMissing_ThenReturnsGeneratedDebugCode()
    {
        await using var dbContext = fixture.CreateDbContext();
        var challengeService = new FakeAuthChallengeService(dbContext);
        var sessionService = new FakeSessionService();
        var currentUserAccessor = new FakeCurrentUserAccessor();
        var sut = fixture.CreateSut(dbContext, challengeService, sessionService, currentUserAccessor,
            returnDebugCodes: true);

        var result = await sut.PasswordResetAsync(
            new PasswordResetRequest("missing@example.com"),
            CancellationToken.None);

        Assert.Equal(ResultStatus.Ok, result.Status);
        Assert.NotNull(result.Value);
        Assert.False(string.IsNullOrWhiteSpace(result.Value!.Code));
    }

    [Fact]
    public async Task PasswordResetVerifyAsync_WhenTargetPhoneDoesNotMatchUser_ThenReturnsBadRequest()
    {
        await using var dbContext = fixture.CreateDbContext();
        var user = await fixture.SeedUserAsync(
            dbContext,
            UserRoles.Client,
            "mismatch@example.com",
            "+31677778888",
            "Str0ng!Pass10");

        var challenge = fixture.BuildTransientChallenge(user, ChallengePurpose.PasswordReset, "+31600000000");
        var challengeService = new FakeAuthChallengeService(dbContext)
        {
            NextGetActiveResult = Result<UserAuthChallenge>.Ok(challenge),
            NextVerifyResult = Result.Ok()
        };
        var sessionService = new FakeSessionService();
        var currentUserAccessor = new FakeCurrentUserAccessor();
        var sut = fixture.CreateSut(dbContext, challengeService, sessionService, currentUserAccessor,
            returnDebugCodes: false);

        var result = await sut.PasswordResetVerifyAsync(
            new PasswordResetVerifyRequest(challenge.Id, "555555"),
            CancellationToken.None);

        Assert.Equal(ResultStatus.BadRequest, result.Status);
        Assert.Equal(0, challengeService.VerifyCallCount);
    }

    [Fact]
    public async Task PasswordResetVerifyAsync_WhenCodeIsValid_ThenReturnsOkWithoutChangingPasswordOrSessions()
    {
        await using var dbContext = fixture.CreateDbContext();
        var user = await fixture.SeedUserAsync(
            dbContext,
            UserRoles.Client,
            "resetverify@example.com",
            "+31688889999",
            "OldPassword!1");

        user.MustChangePassword = true;
        await fixture.SeedSessionAsync(dbContext, user, revoked: false);
        await fixture.SeedSessionAsync(dbContext, user, revoked: false);
        await fixture.SeedSessionAsync(dbContext, user, revoked: true);

        var oldPasswordHash = user.PasswordHash;
        var challenge = fixture.BuildTransientChallenge(user, ChallengePurpose.PasswordReset, user.PhoneE164);

        var challengeService = new FakeAuthChallengeService(dbContext)
        {
            NextGetActiveResult = Result<UserAuthChallenge>.Ok(challenge),
            NextVerifyResult = Result.Ok()
        };
        var sessionService = new FakeSessionService();
        var currentUserAccessor = new FakeCurrentUserAccessor();
        var sut = fixture.CreateSut(dbContext, challengeService, sessionService, currentUserAccessor,
            returnDebugCodes: false);

        var result = await sut.PasswordResetVerifyAsync(
            new PasswordResetVerifyRequest(challenge.Id, "666666"),
            CancellationToken.None);

        Assert.Equal(ResultStatus.Ok, result.Status);
        Assert.Equal(1, challengeService.VerifyCallCount);

        var refreshedUser = await dbContext.Users.SingleAsync(u => u.Id == user.Id);
        Assert.Equal(oldPasswordHash, refreshedUser.PasswordHash);
        Assert.True(refreshedUser.MustChangePassword);

        var allSessions = await dbContext.Sessions.Where(s => s.UserId == user.Id).ToListAsync();
        Assert.NotEmpty(allSessions);
        Assert.Equal(2, allSessions.Count(session => session.RevokedAt == null));
        Assert.Equal(1, allSessions.Count(session => session.RevokedAt != null));
    }

    [Fact]
    public async Task PasswordResetChangeAsync_WhenChallengeIsNotVerified_ThenReturnsUnauthorized()
    {
        await using var dbContext = fixture.CreateDbContext();
        var user = await fixture.SeedUserAsync(
            dbContext,
            UserRoles.Client,
            "change-unverified@example.com",
            "+31677778888",
            "OldPassword!1");

        var oldPasswordHash = user.PasswordHash;
        var challenge = await SeedPasswordResetChallengeAsync(
            dbContext,
            user,
            targetPhoneE164: user.PhoneE164,
            verifiedAt: null);

        var challengeService = new FakeAuthChallengeService(dbContext);
        var sessionService = new FakeSessionService();
        var currentUserAccessor = new FakeCurrentUserAccessor();
        var sut = fixture.CreateSut(dbContext, challengeService, sessionService, currentUserAccessor,
            returnDebugCodes: false);

        var result = await sut.PasswordResetChangeAsync(
            new PasswordResetChangeRequest(challenge.Id, "N3wPassword!2"),
            CancellationToken.None);

        Assert.Equal(ResultStatus.Unauthorized, result.Status);

        var refreshedUser = await dbContext.Users.SingleAsync(u => u.Id == user.Id);
        Assert.Equal(oldPasswordHash, refreshedUser.PasswordHash);
    }

    [Fact]
    public async Task PasswordResetChangeAsync_WhenChallengeIsVerified_ThenUpdatesPasswordAndRevokesActiveSessions()
    {
        await using var dbContext = fixture.CreateDbContext();
        var user = await fixture.SeedUserAsync(
            dbContext,
            UserRoles.Client,
            "change-verified@example.com",
            "+31688889999",
            "OldPassword!1");

        user.MustChangePassword = true;
        await fixture.SeedSessionAsync(dbContext, user, revoked: false);
        await fixture.SeedSessionAsync(dbContext, user, revoked: false);
        await fixture.SeedSessionAsync(dbContext, user, revoked: true);
        var oldPasswordHash = user.PasswordHash;

        var challenge = await SeedPasswordResetChallengeAsync(
            dbContext,
            user,
            targetPhoneE164: user.PhoneE164,
            verifiedAt: DateTime.UtcNow.AddSeconds(-1));

        var challengeService = new FakeAuthChallengeService(dbContext);
        var sessionService = new FakeSessionService();
        var currentUserAccessor = new FakeCurrentUserAccessor();
        var sut = fixture.CreateSut(dbContext, challengeService, sessionService, currentUserAccessor,
            returnDebugCodes: false);

        var result = await sut.PasswordResetChangeAsync(
            new PasswordResetChangeRequest(challenge.Id, "N3wPassword!2"),
            CancellationToken.None);

        Assert.Equal(ResultStatus.Ok, result.Status);

        var refreshedUser = await dbContext.Users.SingleAsync(u => u.Id == user.Id);
        Assert.NotEqual(oldPasswordHash, refreshedUser.PasswordHash);
        var verifyResult =
            fixture.PasswordHasher.VerifyHashedPassword(refreshedUser, refreshedUser.PasswordHash, "N3wPassword!2");
        Assert.NotEqual(PasswordVerificationResult.Failed, verifyResult);
        Assert.False(refreshedUser.MustChangePassword);

        var allSessions = await dbContext.Sessions.Where(s => s.UserId == user.Id).ToListAsync();
        Assert.NotEmpty(allSessions);
        Assert.All(allSessions, session => Assert.NotNull(session.RevokedAt));

        var refreshedChallenge = await dbContext.UserAuthChallenges.SingleAsync(c => c.Id == challenge.Id);
        Assert.True(refreshedChallenge.ExpiresAt <= DateTime.UtcNow);
    }

    [Fact]
    public async Task PasswordResetChangeAsync_WhenTargetPhoneDoesNotMatchUser_ThenReturnsBadRequest()
    {
        await using var dbContext = fixture.CreateDbContext();
        var user = await fixture.SeedUserAsync(
            dbContext,
            UserRoles.Client,
            "change-mismatch@example.com",
            "+31633334444",
            "OldPassword!1");

        var oldPasswordHash = user.PasswordHash;
        var challenge = await SeedPasswordResetChallengeAsync(
            dbContext,
            user,
            targetPhoneE164: "+31600000000",
            verifiedAt: DateTime.UtcNow.AddSeconds(-1));

        var challengeService = new FakeAuthChallengeService(dbContext);
        var sessionService = new FakeSessionService();
        var currentUserAccessor = new FakeCurrentUserAccessor();
        var sut = fixture.CreateSut(dbContext, challengeService, sessionService, currentUserAccessor,
            returnDebugCodes: false);

        var result = await sut.PasswordResetChangeAsync(
            new PasswordResetChangeRequest(challenge.Id, "N3wPassword!2"),
            CancellationToken.None);

        Assert.Equal(ResultStatus.BadRequest, result.Status);

        var refreshedUser = await dbContext.Users.SingleAsync(u => u.Id == user.Id);
        Assert.Equal(oldPasswordHash, refreshedUser.PasswordHash);
    }

    [Fact]
    public async Task PasswordResetVerifyAsync_WhenVerificationFails_ThenReturnsFailureAndDoesNotMutateUser()
    {
        await using var dbContext = fixture.CreateDbContext();
        var user = await fixture.SeedUserAsync(
            dbContext,
            UserRoles.Client,
            "passwordreset-fail@example.com",
            "+31610005555",
            "OldPassword!1");

        user.MustChangePassword = true;
        await dbContext.SaveChangesAsync();

        var oldPasswordHash = user.PasswordHash;
        var challenge = fixture.BuildTransientChallenge(user, ChallengePurpose.PasswordReset, user.PhoneE164);
        var challengeService = new FakeAuthChallengeService(dbContext)
        {
            NextGetActiveResult = Result<UserAuthChallenge>.Ok(challenge),
            NextVerifyResult = Result.Unauthorized()
        };
        var sessionService = new FakeSessionService();
        var currentUserAccessor = new FakeCurrentUserAccessor();
        var sut = fixture.CreateSut(dbContext, challengeService, sessionService, currentUserAccessor,
            returnDebugCodes: false);

        var result = await sut.PasswordResetVerifyAsync(
            new PasswordResetVerifyRequest(challenge.Id, "999999"),
            CancellationToken.None);

        Assert.Equal(ResultStatus.Unauthorized, result.Status);
        Assert.Equal(1, challengeService.VerifyCallCount);

        var refreshedUser = await dbContext.Users.SingleAsync(u => u.Id == user.Id);
        Assert.Equal(oldPasswordHash, refreshedUser.PasswordHash);
        Assert.True(refreshedUser.MustChangePassword);
    }

    private static async Task<UserAuthChallenge> SeedPasswordResetChallengeAsync(
        AppDbContext dbContext,
        User user,
        string? targetPhoneE164,
        DateTime? verifiedAt)
    {
        var now = DateTime.UtcNow;
        var challenge = new UserAuthChallenge
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            User = user,
            Purpose = ChallengePurpose.PasswordReset.ToValue(),
            TargetPhoneE164 = targetPhoneE164,
            CodeHash = Guid.NewGuid().ToByteArray(),
            AttemptCount = 0,
            ResendCount = 0,
            CreatedAt = now.AddMinutes(-1),
            ExpiresAt = now.AddMinutes(5),
            VerifiedAt = verifiedAt
        };

        dbContext.UserAuthChallenges.Add(challenge);
        await dbContext.SaveChangesAsync();
        return challenge;
    }

    [Fact]
    public async Task ResendChallengeCodeAsync_WhenResendFails_ThenReturnsGenericOkResponse()
    {
        await using var dbContext = fixture.CreateDbContext();
        var challengeService = new FakeAuthChallengeService(dbContext)
        {
            NextResendResult = Result<AuthChallengeResendResult>.TooManyRequests()
        };
        var sessionService = new FakeSessionService();
        var currentUserAccessor = new FakeCurrentUserAccessor();
        var sut = fixture.CreateSut(dbContext, challengeService, sessionService, currentUserAccessor,
            returnDebugCodes: false);

        var challengeId = Guid.NewGuid();
        var result = await sut.ResendChallengeCodeAsync(new ResendCodeRequest(challengeId), CancellationToken.None);

        Assert.Equal(ResultStatus.Ok, result.Status);
        Assert.NotNull(result.Value);
        Assert.Equal(challengeId, result.Value!.ChallengeId);
        Assert.Null(result.Value.Code);
    }

    [Fact]
    public async Task ResendChallengeCodeAsync_WhenResendSucceeds_ThenReturnsPayload()
    {
        await using var dbContext = fixture.CreateDbContext();
        var requesterId = Guid.NewGuid();
        var challengeService = new FakeAuthChallengeService(dbContext)
        {
            NextResendResult = Result<AuthChallengeResendResult>.Ok(
                new AuthChallengeResendResult(Guid.NewGuid(), "777888"))
        };
        var sessionService = new FakeSessionService();
        var currentUserAccessor = new FakeCurrentUserAccessor { UserId = requesterId };
        var sut = fixture.CreateSut(dbContext, challengeService, sessionService, currentUserAccessor,
            returnDebugCodes: true);

        var result = await sut.ResendChallengeCodeAsync(new ResendCodeRequest(Guid.NewGuid()), CancellationToken.None);

        Assert.Equal(ResultStatus.Ok, result.Status);
        Assert.NotNull(result.Value);
        Assert.Equal(challengeService.NextResendResult.Value!.ChallengeId, result.Value!.ChallengeId);
        Assert.Equal("777888", result.Value.Code);

        Assert.Equal(1, challengeService.ResendCallCount);
        Assert.Equal(requesterId, challengeService.LastResendRequesterUserId);
    }

    [Fact]
    public async Task ResendChallengeCodeAsync_WhenResendFailsAndDebugEnabled_ThenReturnsDebugCode()
    {
        await using var dbContext = fixture.CreateDbContext();
        var challengeService = new FakeAuthChallengeService(dbContext)
        {
            NextResendResult = Result<AuthChallengeResendResult>.TooManyRequests()
        };
        var sessionService = new FakeSessionService();
        var currentUserAccessor = new FakeCurrentUserAccessor();
        var sut = fixture.CreateSut(dbContext, challengeService, sessionService, currentUserAccessor,
            returnDebugCodes: true);

        var result = await sut.ResendChallengeCodeAsync(new ResendCodeRequest(Guid.NewGuid()), CancellationToken.None);

        Assert.Equal(ResultStatus.Ok, result.Status);
        Assert.NotNull(result.Value);
        Assert.False(string.IsNullOrWhiteSpace(result.Value!.Code));
    }
}

public sealed class AuthServiceFixture
{
    private const string SessionTokenKey = "01234567890123456789012345678901";

    public PasswordHasher<User> PasswordHasher { get; } = new();
    public static readonly DateTime FixedTimestampUtc = new(2025, 2, 1, 12, 0, 0, DateTimeKind.Utc);

    public AppDbContext CreateDbContext()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseInMemoryDatabase($"auth-service-tests-{Guid.NewGuid():N}")
            .Options;

        var dbContext = new AppDbContext(options);
        dbContext.Database.EnsureCreated();
        return dbContext;
    }

    public AuthService CreateSut(
        AppDbContext dbContext,
        FakeAuthChallengeService challengeService,
        FakeSessionService sessionService,
        FakeCurrentUserAccessor currentUserAccessor,
        bool returnDebugCodes)
    {
        var options = Options.Create(new AuthOptions
        {
            SessionTokenKey = SessionTokenKey,
            ReturnDebugCodes = returnDebugCodes
        });

        return new AuthService(
            dbContext,
            challengeService,
            sessionService,
            currentUserAccessor,
            PasswordHasher,
            options);
    }

    public async Task<User> SeedUserAsync(
        AppDbContext dbContext,
        string role,
        string email,
        string phoneE164,
        string password,
        bool isActive = true,
        bool isVerified = true)
    {
        var user = new User
        {
            Id = Guid.NewGuid(),
            Name = $"user-{Guid.NewGuid():N}",
            Email = IdentifierNormalization.NormalizeEmail(email),
            PhoneE164 = IdentifierNormalization.NormalizePhoneE164(phoneE164),
            Role = role,
            MustChangePassword = false,
            IsActive = isActive,
            IsVerified = isVerified,
            CreatedAt = FixedTimestampUtc,
            UpdatedAt = FixedTimestampUtc
        };

        user.PasswordHash = PasswordHasher.HashPassword(user, password);

        dbContext.Users.Add(user);
        await dbContext.SaveChangesAsync();

        return user;
    }

    public async Task<Session> SeedSessionAsync(AppDbContext dbContext, User user, bool revoked)
    {
        var now = FixedTimestampUtc;
        var session = new Session
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
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

    public UserAuthChallenge BuildTransientChallenge(User user, ChallengePurpose purpose, string? targetPhoneE164)
    {
        var code = "111111";
        var codeHash = Lumenary.Infrastructure.Security.Verification.VerificationCodeUtilities.ComputeHash(code, null);

        return new UserAuthChallenge
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            User = user,
            Purpose = purpose.ToValue(),
            TargetPhoneE164 = targetPhoneE164,
            CodeHash = codeHash,
            AttemptCount = 0,
            ResendCount = 0,
            CreatedAt = FixedTimestampUtc,
            ExpiresAt = FixedTimestampUtc.AddMinutes(5)
        };
    }
}

public sealed class FakeAuthChallengeService(AppDbContext dbContext) : IAuthChallengeService
{
    private readonly AppDbContext _dbContext = dbContext;

    public int CreateCallCount { get; private set; }
    public int VerifyCallCount { get; private set; }
    public int ResendCallCount { get; private set; }

    public AuthChallengeRequest? LastCreateRequest { get; private set; }
    public Guid? LastResendRequesterUserId { get; private set; }

    public bool SaveChangesOnCreate { get; set; } = true;
    public AuthChallengeCreation NextCreateResult { get; set; } = new(Guid.NewGuid(), "111111");
    public Result<UserAuthChallenge> NextGetActiveResult { get; set; } = Result<UserAuthChallenge>.Unauthorized();
    public Result NextVerifyResult { get; set; } = Result.Unauthorized();
    public Result<AuthChallengeResendResult> NextResendResult { get; set; } = Result<AuthChallengeResendResult>.TooManyRequests();

    public async Task<AuthChallengeCreation> CreateChallengeAsync(
        AuthChallengeRequest request,
        DateTime now,
        CancellationToken cancellationToken)
    {
        CreateCallCount += 1;
        LastCreateRequest = request;

        if (SaveChangesOnCreate)
            await _dbContext.SaveChangesAsync(cancellationToken);

        return NextCreateResult;
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
    {
        ResendCallCount += 1;
        LastResendRequesterUserId = requesterUserId;
        return Task.FromResult(NextResendResult);
    }
}

public sealed class FakeSessionService : ISessionService
{
    public int CreateCallCount { get; private set; }
    public Guid? LastCreatedUserId { get; private set; }

    public Task CreateSessionAndSetCookieAsync(User user, DateTime now, CancellationToken cancellationToken)
    {
        CreateCallCount += 1;
        LastCreatedUserId = user.Id;
        return Task.CompletedTask;
    }

    public void ClearSessionCookie()
    {
    }
}

public sealed class FakeCurrentUserAccessor : ICurrentUserAccessor
{
    public Guid? UserId { get; init; }

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
        sessionId = Guid.Empty;
        return false;
    }

    public bool TryGetRole(out string? role)
    {
        role = null;
        return false;
    }
}
