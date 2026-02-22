using Lumenary.Api.Common.Validation;
using Lumenary.Common.Validation;

namespace Lumenary.Api.Contracts.Auth;

public sealed record ChangePhoneVerifyRequest(
    [param: NotEmptyGuid] Guid ChallengeId,
    [param: VerificationCode] string Code);
