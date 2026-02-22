using Lumenary.Api.Common.Validation;

namespace Lumenary.Api.Contracts.Auth;

public sealed record PasswordResetVerifyRequest(
    [param: NotEmptyGuid] Guid ChallengeId,
    [param: VerificationCode] string Code);
