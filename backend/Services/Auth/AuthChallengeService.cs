using backend.Auth.Challenges;
using backend.Auth.Options;
using backend.Auth.Verification;
using backend.Data;
using backend.Models;
using backend.Services.Auth.ResendPolicies;
using backend.Services.Results;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace backend.Services.Auth;

public sealed class AuthChallengeService(
    AppDbContext dbContext,
    IOptions<AuthOptions> options,
    IEnumerable<IChallengeResendPolicy> resendPolicies)
    : IAuthChallengeService
{
    private readonly AuthOptions _options = options.Value;
    private readonly string? _verificationCodeKey =
        options.Value.VerificationCodeKey ?? options.Value.SessionTokenKey;

    private readonly IReadOnlyDictionary<ChallengePurpose, IChallengeResendPolicy> _resendPolicies =
        resendPolicies.ToDictionary(policy => policy.Purpose);

    public async Task<AuthChallengeCreation> CreateChallengeAsync(
        AuthChallengeRequest request,
        DateTime now,
        CancellationToken cancellationToken)
    {
        var code = VerificationCodeUtilities.CreateCode();
        var codeHash = VerificationCodeUtilities.ComputeHash(code, _verificationCodeKey);
        var expiresAt = GetExpiresAt(now, now);

        var challenge = new UserAuthChallenge
        {
            UserId = request.UserId,
            Purpose = request.Purpose.ToValue(),
            TargetEmail = request.TargetEmail,
            TargetPhoneE164 = request.TargetPhoneE164,
            CodeHash = codeHash,
            AttemptCount = 0,
            ResendCount = 0,
            CreatedAt = now,
            LastResentAt = null,
            ExpiresAt = expiresAt
        };

        if (request.ChallengeId.HasValue)
            challenge.Id = request.ChallengeId.Value;

        dbContext.UserAuthChallenges.Add(challenge);
        await dbContext.SaveChangesAsync(cancellationToken);

        return new AuthChallengeCreation(challenge.Id, code);
    }

    public async Task<Result<UserAuthChallenge>> GetActiveChallengeAsync(
        Guid challengeId,
        ChallengePurpose purpose,
        Guid? userId,
        DateTime now,
        CancellationToken cancellationToken)
    {
        var query = dbContext.UserAuthChallenges
            .Include(c => c.User)
            .Where(c => c.Id == challengeId &&
                        c.Purpose == purpose.ToValue() &&
                        c.VerifiedAt == null &&
                        c.ExpiresAt > now);

        if (userId.HasValue)
            query = query.Where(c => c.UserId == userId.Value);

        var challenge = await query.FirstOrDefaultAsync(cancellationToken);
        if (challenge == null || !challenge.User.IsActive)
            return Result<UserAuthChallenge>.Unauthorized();

        return Result<UserAuthChallenge>.Ok(challenge);
    }

    public async Task<Result> VerifyChallengeCodeAsync(
        UserAuthChallenge challenge,
        string code,
        DateTime now,
        CancellationToken cancellationToken)
    {
        if (challenge.AttemptCount >= AuthChallengePolicy.MaxAttempts)
            return Result.TooManyRequests();

        var providedHash = VerificationCodeUtilities.ComputeHash(code, _verificationCodeKey);
        if (!challenge.CodeHash.SequenceEqual(providedHash))
        {
            challenge.AttemptCount += 1;

            if (challenge.AttemptCount >= AuthChallengePolicy.MaxAttempts)
                challenge.ExpiresAt = now;

            await dbContext.SaveChangesAsync(cancellationToken);
            return Result.Unauthorized();
        }

        challenge.VerifiedAt = now;
        return Result.Ok();
    }

    public async Task<Result<AuthChallengeResendResult>> ResendChallengeAsync(
        Guid challengeId,
        Guid? requesterUserId,
        DateTime now,
        CancellationToken cancellationToken)
    {
        var challenge = await dbContext.UserAuthChallenges
            .Include(c => c.User)
            .Where(c => c.Id == challengeId &&
                        c.VerifiedAt == null &&
                        c.ExpiresAt > now)
            .FirstOrDefaultAsync(cancellationToken);

        if (challenge == null || !challenge.User.IsActive)
            return Result<AuthChallengeResendResult>.NotFound();

        if (!ChallengePurposeExtensions.TryParse(challenge.Purpose, out var purpose) ||
            !_resendPolicies.TryGetValue(purpose, out var policy))
            return Result<AuthChallengeResendResult>.BadRequest();

        var policyResult = policy.Validate(challenge, requesterUserId);
        if (!policyResult.IsSuccess)
        {
            return policyResult.Status switch
            {
                ResultStatus.Unauthorized => Result<AuthChallengeResendResult>.Unauthorized(),
                ResultStatus.BadRequest => Result<AuthChallengeResendResult>.BadRequest(),
                ResultStatus.TooManyRequests => Result<AuthChallengeResendResult>.TooManyRequests(),
                _ => Result<AuthChallengeResendResult>.BadRequest()
            };
        }

        if (challenge.AttemptCount >= AuthChallengePolicy.MaxAttempts ||
            challenge.ResendCount >= AuthChallengePolicy.MaxResends)
            return Result<AuthChallengeResendResult>.TooManyRequests();

        var maxLifetimeAt = challenge.CreatedAt.AddMinutes(AuthChallengePolicy.MaxLifetimeMinutes);
        if (maxLifetimeAt <= now)
            return Result<AuthChallengeResendResult>.TooManyRequests();

        if (challenge.LastResentAt.HasValue &&
            challenge.LastResentAt.Value
                .AddSeconds(AuthChallengePolicy.ResendCooldownSeconds) > now)
            return Result<AuthChallengeResendResult>.TooManyRequests();

        var code = VerificationCodeUtilities.CreateCode();
        challenge.CodeHash = VerificationCodeUtilities.ComputeHash(code, _verificationCodeKey);
        challenge.ResendCount += 1;
        challenge.LastResentAt = now;
        challenge.ExpiresAt = GetExpiresAt(challenge.CreatedAt, now);

        await dbContext.SaveChangesAsync(cancellationToken);

        var responseCode =
            purpose is ChallengePurpose.Login or ChallengePurpose.Register
                ? code
                : null;

        return Result<AuthChallengeResendResult>.Ok(
            new AuthChallengeResendResult(challenge.Id, responseCode));
    }

    private DateTime GetExpiresAt(DateTime createdAt, DateTime now)
    {
        var ttlExpiresAt = now.AddMinutes(_options.LoginCodeTtlMinutes);
        var maxLifetimeAt = createdAt.AddMinutes(AuthChallengePolicy.MaxLifetimeMinutes);
        return ttlExpiresAt <= maxLifetimeAt ? ttlExpiresAt : maxLifetimeAt;
    }
}