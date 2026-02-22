using Lumenary.Features.Auth.Challenges;
using Lumenary.Persistence.Entities;
using Lumenary.Common.Results;

namespace Lumenary.Features.Auth.ResendPolicies;

public sealed class PasswordResetResendPolicy : IChallengeResendPolicy
{
    public ChallengePurpose Purpose => ChallengePurpose.PasswordReset;

    public Result Validate(UserAuthChallenge challenge, Guid? requesterUserId)
    {
        if (string.IsNullOrWhiteSpace(challenge.TargetPhoneE164) ||
            !string.Equals(challenge.TargetPhoneE164, challenge.User.PhoneE164, StringComparison.Ordinal))
        {
            return Result.BadRequest();
        }

        return Result.Ok();
    }
}
