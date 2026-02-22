using Lumenary.Api.Common.Validation;
using Lumenary.Common.Validation;

namespace Lumenary.Api.Contracts.Auth;

public sealed record ChangeEmailCancelRequest(
    [param: NotEmptyGuid] Guid ChallengeId);
