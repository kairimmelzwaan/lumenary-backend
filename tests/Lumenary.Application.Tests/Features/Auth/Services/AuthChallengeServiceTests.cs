using Lumenary.Features.Auth.Challenges;
using Lumenary.Application.Common.Options;
using Lumenary.Infrastructure.Security.Verification;
using Lumenary.Persistence;
using Lumenary.Domain.ValueObjects;
using Lumenary.Persistence.Entities;
using Lumenary.Features.Auth.Services;
using Lumenary.Features.Auth.ResendPolicies;
using Lumenary.Common.Results;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Lumenary.Tests.Features.Auth.Services;

public sealed class AuthChallengeServiceTests(AuthChallengeServiceFixture fixture)
    : IClassFixture<AuthChallengeServiceFixture>
{
    [Fact]
    public async Task CreateChallengeAsync_WhenCalled_ThenPersistsChallengeWithExpectedValues()
    {
        await using var dbContext = fixture.CreateDbContext();
        var user = await fixture.SeedUserAsync(dbContext, UserRoles.Client, "+31610000001");
        var sut = fixture.CreateSut(dbContext);
        var now = AuthChallengeServiceFixture.FixedTimestampUtc;

        var result = await sut.CreateChallengeAsync(
            new AuthChallengeRequest(user.Id, ChallengePurpose.Login, null, user.PhoneE164),
            now,
            CancellationToken.None);

        var challenge = await dbContext.UserAuthChallenges.SingleAsync(c => c.Id == result.ChallengeId);

        Assert.Equal(user.Id, challenge.UserId);
        Assert.Equal(ChallengePurpose.Login.ToValue(), challenge.Purpose);
        Assert.Equal(user.PhoneE164, challenge.TargetPhoneE164);
        Assert.Equal(0, challenge.AttemptCount);
        Assert.Equal(0, challenge.ResendCount);
        Assert.Null(challenge.VerifiedAt);
        Assert.Equal(now.AddMinutes(AuthChallengeServiceFixture.LoginCodeTtlMinutes), challenge.ExpiresAt);

        var expectedHash = VerificationCodeUtilities.ComputeHash(result.Code, AuthChallengeServiceFixture.VerificationCodeKey);
        Assert.True(challenge.CodeHash.SequenceEqual(expectedHash));
    }

    [Fact]
    public async Task GetActiveChallengeAsync_WhenChallengeDoesNotExist_ThenReturnsUnauthorized()
    {
        await using var dbContext = fixture.CreateDbContext();
        var sut = fixture.CreateSut(dbContext);

        var result = await sut.GetActiveChallengeAsync(
            Guid.NewGuid(),
            ChallengePurpose.Login,
            null,
            AuthChallengeServiceFixture.FixedTimestampUtc,
            CancellationToken.None);

        Assert.Equal(ResultStatus.Unauthorized, result.Status);
    }

    [Fact]
    public async Task GetActiveChallengeAsync_WhenUserIsInactive_ThenReturnsUnauthorized()
    {
        await using var dbContext = fixture.CreateDbContext();
        var user = await fixture.SeedUserAsync(dbContext, UserRoles.Client, "+31610000002", isActive: false);
        var now = AuthChallengeServiceFixture.FixedTimestampUtc;
        var challenge = await fixture.SeedChallengeAsync(
            dbContext,
            user,
            ChallengePurpose.Login,
            "123456",
            now.AddMinutes(-1),
            now.AddMinutes(5));
        var sut = fixture.CreateSut(dbContext);

        var result = await sut.GetActiveChallengeAsync(
            challenge.Id,
            ChallengePurpose.Login,
            null,
            now,
            CancellationToken.None);

        Assert.Equal(ResultStatus.Unauthorized, result.Status);
    }

    [Fact]
    public async Task GetActiveChallengeAsync_WhenPurposeDoesNotMatch_ThenReturnsUnauthorized()
    {
        await using var dbContext = fixture.CreateDbContext();
        var user = await fixture.SeedUserAsync(dbContext, UserRoles.Client, "+31610000012");
        var now = AuthChallengeServiceFixture.FixedTimestampUtc;
        var challenge = await fixture.SeedChallengeAsync(
            dbContext,
            user,
            ChallengePurpose.Login,
            "123456",
            now.AddMinutes(-1),
            now.AddMinutes(5));
        var sut = fixture.CreateSut(dbContext);

        var result = await sut.GetActiveChallengeAsync(
            challenge.Id,
            ChallengePurpose.Register,
            null,
            now,
            CancellationToken.None);

        Assert.Equal(ResultStatus.Unauthorized, result.Status);
    }

    [Fact]
    public async Task GetActiveChallengeAsync_WhenUserFilterDoesNotMatch_ThenReturnsUnauthorized()
    {
        await using var dbContext = fixture.CreateDbContext();
        var user = await fixture.SeedUserAsync(dbContext, UserRoles.Client, "+31610000013");
        var now = AuthChallengeServiceFixture.FixedTimestampUtc;
        var challenge = await fixture.SeedChallengeAsync(
            dbContext,
            user,
            ChallengePurpose.ChangeEmail,
            "123456",
            now.AddMinutes(-1),
            now.AddMinutes(5),
            targetEmail: "next@example.com");
        var sut = fixture.CreateSut(dbContext);

        var result = await sut.GetActiveChallengeAsync(
            challenge.Id,
            ChallengePurpose.ChangeEmail,
            Guid.NewGuid(),
            now,
            CancellationToken.None);

        Assert.Equal(ResultStatus.Unauthorized, result.Status);
    }

    [Fact]
    public async Task VerifyChallengeCodeAsync_WhenAttemptLimitAlreadyReached_ThenReturnsTooManyRequests()
    {
        await using var dbContext = fixture.CreateDbContext();
        var user = await fixture.SeedUserAsync(dbContext, UserRoles.Client, "+31610000003");
        var now = AuthChallengeServiceFixture.FixedTimestampUtc;
        var challenge = await fixture.SeedChallengeAsync(
            dbContext,
            user,
            ChallengePurpose.Login,
            "123456",
            now.AddMinutes(-1),
            now.AddMinutes(5),
            attemptCount: AuthChallengePolicy.MaxAttempts);
        var sut = fixture.CreateSut(dbContext);

        var result = await sut.VerifyChallengeCodeAsync(challenge, "123456", now, CancellationToken.None);

        Assert.Equal(ResultStatus.TooManyRequests, result.Status);
    }

    [Fact]
    public async Task VerifyChallengeCodeAsync_WhenWrongCodeAtFinalAttempt_ThenIncrementsAttemptsAndExpiresChallenge()
    {
        await using var dbContext = fixture.CreateDbContext();
        var user = await fixture.SeedUserAsync(dbContext, UserRoles.Client, "+31610000004");
        var now = AuthChallengeServiceFixture.FixedTimestampUtc;
        var challenge = await fixture.SeedChallengeAsync(
            dbContext,
            user,
            ChallengePurpose.Login,
            "123456",
            now.AddMinutes(-1),
            now.AddMinutes(5),
            attemptCount: AuthChallengePolicy.MaxAttempts - 1);
        var sut = fixture.CreateSut(dbContext);

        var result = await sut.VerifyChallengeCodeAsync(challenge, "999999", now, CancellationToken.None);

        Assert.Equal(ResultStatus.Unauthorized, result.Status);

        var refreshed = await dbContext.UserAuthChallenges.SingleAsync(c => c.Id == challenge.Id);
        Assert.Equal(AuthChallengePolicy.MaxAttempts, refreshed.AttemptCount);
        Assert.Equal(now, refreshed.ExpiresAt);
    }

    [Fact]
    public async Task VerifyChallengeCodeAsync_WhenCodeIsValid_ThenMarksChallengeVerified()
    {
        await using var dbContext = fixture.CreateDbContext();
        var user = await fixture.SeedUserAsync(dbContext, UserRoles.Client, "+31610000005");
        var now = AuthChallengeServiceFixture.FixedTimestampUtc;
        var challenge = await fixture.SeedChallengeAsync(
            dbContext,
            user,
            ChallengePurpose.Login,
            "555555",
            now.AddMinutes(-1),
            now.AddMinutes(5));
        var sut = fixture.CreateSut(dbContext);

        var result = await sut.VerifyChallengeCodeAsync(challenge, "555555", now, CancellationToken.None);

        Assert.Equal(ResultStatus.Ok, result.Status);
        Assert.Equal(now, challenge.VerifiedAt);
    }

    [Fact]
    public async Task VerifyChallengeCodeAsync_WhenStoredHashLengthIsInvalid_ThenReturnsUnauthorizedAndIncrementsAttempts()
    {
        await using var dbContext = fixture.CreateDbContext();
        var user = await fixture.SeedUserAsync(dbContext, UserRoles.Client, "+31610000014");
        var now = AuthChallengeServiceFixture.FixedTimestampUtc;
        var challenge = await fixture.SeedChallengeAsync(
            dbContext,
            user,
            ChallengePurpose.Login,
            "555555",
            now.AddMinutes(-1),
            now.AddMinutes(5));

        challenge.CodeHash = new byte[31];
        await dbContext.SaveChangesAsync();

        var sut = fixture.CreateSut(dbContext);

        var result = await sut.VerifyChallengeCodeAsync(challenge, "555555", now, CancellationToken.None);

        Assert.Equal(ResultStatus.Unauthorized, result.Status);
        Assert.Equal(1, challenge.AttemptCount);
    }

    [Fact]
    public async Task ResendChallengeAsync_WhenChallengeMissing_ThenReturnsNotFound()
    {
        await using var dbContext = fixture.CreateDbContext();
        var sut = fixture.CreateSut(dbContext);

        var result = await sut.ResendChallengeAsync(
            Guid.NewGuid(),
            null,
            AuthChallengeServiceFixture.FixedTimestampUtc,
            CancellationToken.None);

        Assert.Equal(ResultStatus.NotFound, result.Status);
    }

    [Fact]
    public async Task ResendChallengeAsync_WhenPurposeIsUnknown_ThenReturnsBadRequest()
    {
        await using var dbContext = fixture.CreateDbContext();
        var user = await fixture.SeedUserAsync(dbContext, UserRoles.Client, "+31610000006");
        var now = AuthChallengeServiceFixture.FixedTimestampUtc;
        var challenge = await fixture.SeedChallengeAsync(
            dbContext,
            user,
            ChallengePurpose.Login,
            "123456",
            now.AddMinutes(-1),
            now.AddMinutes(5),
            purposeValue: "unknown_purpose");
        var sut = fixture.CreateSut(dbContext);

        var result = await sut.ResendChallengeAsync(challenge.Id, null, now, CancellationToken.None);

        Assert.Equal(ResultStatus.BadRequest, result.Status);
    }

    [Fact]
    public async Task ResendChallengeAsync_WhenPolicyRejectsRequester_ThenReturnsUnauthorized()
    {
        await using var dbContext = fixture.CreateDbContext();
        var user = await fixture.SeedUserAsync(dbContext, UserRoles.Client, "+31610000007");
        user.PendingEmail = "next@example.com";
        await dbContext.SaveChangesAsync();

        var now = AuthChallengeServiceFixture.FixedTimestampUtc;
        var challenge = await fixture.SeedChallengeAsync(
            dbContext,
            user,
            ChallengePurpose.ChangeEmail,
            "123456",
            now.AddMinutes(-1),
            now.AddMinutes(5),
            targetEmail: user.PendingEmail);

        var sut = fixture.CreateSut(dbContext);

        var result = await sut.ResendChallengeAsync(challenge.Id, Guid.NewGuid(), now, CancellationToken.None);

        Assert.Equal(ResultStatus.Unauthorized, result.Status);
    }

    [Fact]
    public async Task ResendChallengeAsync_WhenCooldownNotElapsed_ThenReturnsTooManyRequests()
    {
        await using var dbContext = fixture.CreateDbContext();
        var user = await fixture.SeedUserAsync(dbContext, UserRoles.Client, "+31610000008");
        var now = AuthChallengeServiceFixture.FixedTimestampUtc;
        var challenge = await fixture.SeedChallengeAsync(
            dbContext,
            user,
            ChallengePurpose.Login,
            "123456",
            now.AddMinutes(-1),
            now.AddMinutes(5),
            lastResentAt: now.AddSeconds(-(AuthChallengePolicy.ResendCooldownSeconds - 1)));
        var sut = fixture.CreateSut(dbContext);

        var result = await sut.ResendChallengeAsync(challenge.Id, null, now, CancellationToken.None);

        Assert.Equal(ResultStatus.TooManyRequests, result.Status);
    }

    [Fact]
    public async Task ResendChallengeAsync_WhenAttemptLimitReached_ThenReturnsTooManyRequests()
    {
        await using var dbContext = fixture.CreateDbContext();
        var user = await fixture.SeedUserAsync(dbContext, UserRoles.Client, "+31610000015");
        var now = AuthChallengeServiceFixture.FixedTimestampUtc;
        var challenge = await fixture.SeedChallengeAsync(
            dbContext,
            user,
            ChallengePurpose.Login,
            "123456",
            now.AddMinutes(-1),
            now.AddMinutes(5),
            attemptCount: AuthChallengePolicy.MaxAttempts);
        var sut = fixture.CreateSut(dbContext);

        var result = await sut.ResendChallengeAsync(challenge.Id, null, now, CancellationToken.None);

        Assert.Equal(ResultStatus.TooManyRequests, result.Status);
    }

    [Fact]
    public async Task ResendChallengeAsync_WhenResendLimitReached_ThenReturnsTooManyRequests()
    {
        await using var dbContext = fixture.CreateDbContext();
        var user = await fixture.SeedUserAsync(dbContext, UserRoles.Client, "+31610000016");
        var now = AuthChallengeServiceFixture.FixedTimestampUtc;
        var challenge = await fixture.SeedChallengeAsync(
            dbContext,
            user,
            ChallengePurpose.Login,
            "123456",
            now.AddMinutes(-2),
            now.AddMinutes(5),
            resendCount: AuthChallengePolicy.MaxResends);
        var sut = fixture.CreateSut(dbContext);

        var result = await sut.ResendChallengeAsync(challenge.Id, null, now, CancellationToken.None);

        Assert.Equal(ResultStatus.TooManyRequests, result.Status);
    }

    [Fact]
    public async Task ResendChallengeAsync_WhenMaxLifetimeExceeded_ThenReturnsTooManyRequests()
    {
        await using var dbContext = fixture.CreateDbContext();
        var user = await fixture.SeedUserAsync(dbContext, UserRoles.Client, "+31610000017");
        var now = AuthChallengeServiceFixture.FixedTimestampUtc;
        var createdAt = now.AddMinutes(-AuthChallengePolicy.MaxLifetimeMinutes);
        var challenge = await fixture.SeedChallengeAsync(
            dbContext,
            user,
            ChallengePurpose.Login,
            "123456",
            createdAt,
            now.AddMinutes(1));
        var sut = fixture.CreateSut(dbContext);

        var result = await sut.ResendChallengeAsync(challenge.Id, null, now, CancellationToken.None);

        Assert.Equal(ResultStatus.TooManyRequests, result.Status);
    }

    [Fact]
    public async Task ResendChallengeAsync_WhenPasswordResetTargetPhoneMismatch_ThenReturnsBadRequest()
    {
        await using var dbContext = fixture.CreateDbContext();
        var user = await fixture.SeedUserAsync(dbContext, UserRoles.Client, "+31610000009");
        var now = AuthChallengeServiceFixture.FixedTimestampUtc;
        var challenge = await fixture.SeedChallengeAsync(
            dbContext,
            user,
            ChallengePurpose.PasswordReset,
            "123456",
            now.AddMinutes(-1),
            now.AddMinutes(5),
            targetPhoneE164: "+31699999999");
        var sut = fixture.CreateSut(dbContext);

        var result = await sut.ResendChallengeAsync(challenge.Id, null, now, CancellationToken.None);

        Assert.Equal(ResultStatus.BadRequest, result.Status);
    }

    [Fact]
    public async Task ResendChallengeAsync_WhenLoginChallengeIsValid_ThenRotatesCodeAndReturnsResponseCode()
    {
        await using var dbContext = fixture.CreateDbContext();
        var user = await fixture.SeedUserAsync(dbContext, UserRoles.Client, "+31610000010");
        var now = AuthChallengeServiceFixture.FixedTimestampUtc;
        var challenge = await fixture.SeedChallengeAsync(
            dbContext,
            user,
            ChallengePurpose.Login,
            "123456",
            now.AddMinutes(-2),
            now.AddMinutes(5));

        var originalHash = challenge.CodeHash.ToArray();
        var sut = fixture.CreateSut(dbContext);

        var result = await sut.ResendChallengeAsync(challenge.Id, null, now, CancellationToken.None);

        Assert.Equal(ResultStatus.Ok, result.Status);
        Assert.NotNull(result.Value);
        Assert.Equal(challenge.Id, result.Value!.ChallengeId);
        Assert.False(string.IsNullOrWhiteSpace(result.Value.Code));

        var refreshed = await dbContext.UserAuthChallenges.SingleAsync(c => c.Id == challenge.Id);
        Assert.Equal(1, refreshed.ResendCount);
        Assert.Equal(now, refreshed.LastResentAt);
        Assert.Equal(now.AddMinutes(AuthChallengeServiceFixture.LoginCodeTtlMinutes), refreshed.ExpiresAt);

        var expectedHash = VerificationCodeUtilities.ComputeHash(result.Value.Code!, AuthChallengeServiceFixture.VerificationCodeKey);
        Assert.True(refreshed.CodeHash.SequenceEqual(expectedHash));
        Assert.False(refreshed.CodeHash.SequenceEqual(originalHash));
    }

    [Fact]
    public async Task ResendChallengeAsync_WhenPasswordResetChallengeIsValid_ThenReturnsNullCode()
    {
        await using var dbContext = fixture.CreateDbContext();
        var user = await fixture.SeedUserAsync(dbContext, UserRoles.Client, "+31610000011");
        var now = AuthChallengeServiceFixture.FixedTimestampUtc;
        var challenge = await fixture.SeedChallengeAsync(
            dbContext,
            user,
            ChallengePurpose.PasswordReset,
            "123456",
            now.AddMinutes(-2),
            now.AddMinutes(5),
            targetPhoneE164: user.PhoneE164);

        var sut = fixture.CreateSut(dbContext);

        var result = await sut.ResendChallengeAsync(challenge.Id, null, now, CancellationToken.None);

        Assert.Equal(ResultStatus.Ok, result.Status);
        Assert.NotNull(result.Value);
        Assert.Null(result.Value!.Code);
    }
}

public sealed class AuthChallengeServiceFixture
{
    public const int LoginCodeTtlMinutes = 5;
    public const string VerificationCodeKey = "sum-32-character-long-secret-key";
    public static readonly DateTime FixedTimestampUtc = new(2025, 2, 1, 12, 0, 0, DateTimeKind.Utc);

    public AppDbContext CreateDbContext()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseInMemoryDatabase($"auth-challenge-tests-{Guid.NewGuid():N}")
            .Options;

        var dbContext = new AppDbContext(options);
        dbContext.Database.EnsureCreated();
        return dbContext;
    }

    public AuthChallengeService CreateSut(AppDbContext dbContext)
    {
        var options = Options.Create(new AuthOptions
        {
            SessionTokenKey = "01234567890123456789012345678901",
            VerificationCodeKey = VerificationCodeKey,
            LoginCodeTtlMinutes = LoginCodeTtlMinutes
        });

        IChallengeResendPolicy[] policies =
        [
            new LoginResendPolicy(),
            new RegisterResendPolicy(),
            new PasswordResetResendPolicy(),
            new ChangeEmailResendPolicy(),
            new ChangePhoneResendPolicy()
        ];

        return new AuthChallengeService(dbContext, options, policies);
    }

    public async Task<User> SeedUserAsync(
        AppDbContext dbContext,
        string role,
        string phoneE164,
        bool isActive = true)
    {
        var user = new User
        {
            Id = Guid.NewGuid(),
            Name = $"user-{Guid.NewGuid():N}",
            Email = $"{Guid.NewGuid():N}@example.test",
            PhoneE164 = phoneE164,
            PasswordHash = "hash",
            Role = role,
            IsActive = isActive,
            IsVerified = true,
            MustChangePassword = false,
            CreatedAt = FixedTimestampUtc,
            UpdatedAt = FixedTimestampUtc
        };

        dbContext.Users.Add(user);
        await dbContext.SaveChangesAsync();

        return user;
    }

    public async Task<UserAuthChallenge> SeedChallengeAsync(
        AppDbContext dbContext,
        User user,
        ChallengePurpose purpose,
        string code,
        DateTime createdAt,
        DateTime expiresAt,
        int attemptCount = 0,
        int resendCount = 0,
        DateTime? lastResentAt = null,
        DateTime? verifiedAt = null,
        string? targetEmail = null,
        string? targetPhoneE164 = null,
        string? purposeValue = null)
    {
        var challenge = new UserAuthChallenge
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            Purpose = purposeValue ?? purpose.ToValue(),
            TargetEmail = targetEmail,
            TargetPhoneE164 = targetPhoneE164,
            CodeHash = VerificationCodeUtilities.ComputeHash(code, VerificationCodeKey),
            AttemptCount = attemptCount,
            ResendCount = resendCount,
            CreatedAt = createdAt,
            LastResentAt = lastResentAt,
            ExpiresAt = expiresAt,
            VerifiedAt = verifiedAt
        };

        dbContext.UserAuthChallenges.Add(challenge);
        await dbContext.SaveChangesAsync();

        return challenge;
    }
}
