using Lumenary.Api.Common.Validation;
using Lumenary.Common.Validation;

namespace Lumenary.Api.Contracts.Auth;

public sealed record LoginVerifyRequest(
    [param: NotEmptyGuid] Guid ChallengeId,
    [param: VerificationCode] string Code);
