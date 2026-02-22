using Lumenary.Api.Common.Validation;

namespace Lumenary.Api.Contracts.Auth;

public sealed record ResendCodeRequest(
    [param: NotEmptyGuid] Guid ChallengeId);
