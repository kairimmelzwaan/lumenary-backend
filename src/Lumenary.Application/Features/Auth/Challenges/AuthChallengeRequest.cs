using Lumenary.Features.Auth.Challenges;

namespace Lumenary.Features.Auth.Challenges;

public sealed record AuthChallengeRequest(
    Guid UserId,
    ChallengePurpose Purpose,
    string? TargetEmail,
    string? TargetPhoneE164,
    Guid? ChallengeId = null);
