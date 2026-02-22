using Lumenary.Features.Auth.Challenges;
using Lumenary.Persistence.Entities;
using Lumenary.Common.Results;

namespace Lumenary.Features.Auth.ResendPolicies;

public sealed class ChangeEmailResendPolicy : IChallengeResendPolicy
{
    public ChallengePurpose Purpose => ChallengePurpose.ChangeEmail;

    public Result Validate(UserAuthChallenge challenge, Guid? requesterUserId)
    {
        if (!requesterUserId.HasValue || challenge.UserId != requesterUserId.Value)
        {
            return Result.Unauthorized();
        }

        if (string.IsNullOrWhiteSpace(challenge.User.PendingEmail) ||
            !string.Equals(challenge.TargetEmail, challenge.User.PendingEmail, StringComparison.Ordinal))
        {
            return Result.BadRequest();
        }

        return Result.Ok();
    }
}
