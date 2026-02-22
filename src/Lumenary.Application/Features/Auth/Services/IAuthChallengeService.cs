using Lumenary.Features.Auth.Challenges;
using Lumenary.Persistence.Entities;
using Lumenary.Common.Results;

namespace Lumenary.Features.Auth.Services;

public interface IAuthChallengeService
{
    Task<AuthChallengeCreation> CreateChallengeAsync(
        AuthChallengeRequest request,
        DateTime now,
        CancellationToken cancellationToken);

    Task<Result<UserAuthChallenge>> GetActiveChallengeAsync(
        Guid challengeId,
        ChallengePurpose purpose,
        Guid? userId,
        DateTime now,
        CancellationToken cancellationToken);

    Task<Result> VerifyChallengeCodeAsync(
        UserAuthChallenge challenge,
        string code,
        DateTime now,
        CancellationToken cancellationToken);

    Task<Result<AuthChallengeResendResult>> ResendChallengeAsync(
        Guid challengeId,
        Guid? requesterUserId,
        DateTime now,
        CancellationToken cancellationToken);
}
