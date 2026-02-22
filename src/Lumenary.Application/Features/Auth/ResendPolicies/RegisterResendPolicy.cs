using Lumenary.Features.Auth.Challenges;
using Lumenary.Persistence.Entities;
using Lumenary.Common.Results;

namespace Lumenary.Features.Auth.ResendPolicies;

public sealed class RegisterResendPolicy : IChallengeResendPolicy
{
    public ChallengePurpose Purpose => ChallengePurpose.Register;

    public Result Validate(UserAuthChallenge challenge, Guid? requesterUserId)
    {
        return Result.Ok();
    }
}
