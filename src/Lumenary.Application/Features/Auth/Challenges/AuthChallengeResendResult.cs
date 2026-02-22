namespace Lumenary.Features.Auth.Challenges;

public sealed record AuthChallengeResendResult(Guid ChallengeId, string? Code);
