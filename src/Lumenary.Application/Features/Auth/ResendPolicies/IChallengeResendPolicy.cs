using Lumenary.Features.Auth.Challenges;
using Lumenary.Persistence.Entities;
using Lumenary.Common.Results;

namespace Lumenary.Features.Auth.ResendPolicies;

public interface IChallengeResendPolicy
{
    ChallengePurpose Purpose { get; }
    Result Validate(UserAuthChallenge challenge, Guid? requesterUserId);
}
