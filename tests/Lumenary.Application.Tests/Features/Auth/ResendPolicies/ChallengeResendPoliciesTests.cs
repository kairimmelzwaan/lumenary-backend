using Lumenary.Features.Auth.Challenges;
using Lumenary.Persistence.Entities;
using Lumenary.Features.Auth.ResendPolicies;
using Lumenary.Common.Results;

namespace Lumenary.Tests.Features.Auth.ResendPolicies;

public sealed class ChallengeResendPoliciesTests
{
    [Fact]
    public void LoginResendPolicy_WhenValidated_ThenAlwaysReturnsOk()
    {
        var policy = new LoginResendPolicy();
        var challenge = BuildChallenge(ChallengePurpose.Login);

        var result = policy.Validate(challenge, requesterUserId: null);

        Assert.Equal(ResultStatus.Ok, result.Status);
    }

    [Fact]
    public void RegisterResendPolicy_WhenValidated_ThenAlwaysReturnsOk()
    {
        var policy = new RegisterResendPolicy();
        var challenge = BuildChallenge(ChallengePurpose.Register);

        var result = policy.Validate(challenge, requesterUserId: Guid.NewGuid());

        Assert.Equal(ResultStatus.Ok, result.Status);
    }

    [Fact]
    public void PasswordResetResendPolicy_WhenTargetPhoneDoesNotMatchUser_ThenReturnsBadRequest()
    {
        var policy = new PasswordResetResendPolicy();
        var challenge = BuildChallenge(ChallengePurpose.PasswordReset, targetPhoneE164: "+31600000000");

        var result = policy.Validate(challenge, requesterUserId: null);

        Assert.Equal(ResultStatus.BadRequest, result.Status);
    }

    [Fact]
    public void ChangeEmailResendPolicy_WhenRequesterMissingOrMismatched_ThenReturnsUnauthorized()
    {
        var policy = new ChangeEmailResendPolicy();
        var challenge = BuildChallenge(ChallengePurpose.ChangeEmail, targetEmail: "next@example.com");
        challenge.User.PendingEmail = "next@example.com";

        var missingRequester = policy.Validate(challenge, requesterUserId: null);
        var mismatchedRequester = policy.Validate(challenge, requesterUserId: Guid.NewGuid());

        Assert.Equal(ResultStatus.Unauthorized, missingRequester.Status);
        Assert.Equal(ResultStatus.Unauthorized, mismatchedRequester.Status);
    }

    [Fact]
    public void ChangeEmailResendPolicy_WhenPendingEmailDoesNotMatchTarget_ThenReturnsBadRequest()
    {
        var policy = new ChangeEmailResendPolicy();
        var challenge = BuildChallenge(ChallengePurpose.ChangeEmail, targetEmail: "next@example.com");
        challenge.User.PendingEmail = "other@example.com";

        var result = policy.Validate(challenge, challenge.UserId);

        Assert.Equal(ResultStatus.BadRequest, result.Status);
    }

    [Fact]
    public void ChangeEmailResendPolicy_WhenRequesterAndPendingEmailMatch_ThenReturnsOk()
    {
        var policy = new ChangeEmailResendPolicy();
        var challenge = BuildChallenge(ChallengePurpose.ChangeEmail, targetEmail: "next@example.com");
        challenge.User.PendingEmail = "next@example.com";

        var result = policy.Validate(challenge, challenge.UserId);

        Assert.Equal(ResultStatus.Ok, result.Status);
    }

    [Fact]
    public void ChangePhoneResendPolicy_WhenRequesterMissingOrMismatched_ThenReturnsUnauthorized()
    {
        var policy = new ChangePhoneResendPolicy();
        var challenge = BuildChallenge(ChallengePurpose.ChangePhone, targetPhoneE164: "+31699990000");
        challenge.User.PendingPhoneE164 = "+31699990000";

        var missingRequester = policy.Validate(challenge, requesterUserId: null);
        var mismatchedRequester = policy.Validate(challenge, requesterUserId: Guid.NewGuid());

        Assert.Equal(ResultStatus.Unauthorized, missingRequester.Status);
        Assert.Equal(ResultStatus.Unauthorized, mismatchedRequester.Status);
    }

    [Fact]
    public void ChangePhoneResendPolicy_WhenPendingPhoneDoesNotMatchTarget_ThenReturnsBadRequest()
    {
        var policy = new ChangePhoneResendPolicy();
        var challenge = BuildChallenge(ChallengePurpose.ChangePhone, targetPhoneE164: "+31699990000");
        challenge.User.PendingPhoneE164 = "+31611112222";

        var result = policy.Validate(challenge, challenge.UserId);

        Assert.Equal(ResultStatus.BadRequest, result.Status);
    }

    [Fact]
    public void ChangePhoneResendPolicy_WhenRequesterAndPendingPhoneMatch_ThenReturnsOk()
    {
        var policy = new ChangePhoneResendPolicy();
        var challenge = BuildChallenge(ChallengePurpose.ChangePhone, targetPhoneE164: "+31699990000");
        challenge.User.PendingPhoneE164 = "+31699990000";

        var result = policy.Validate(challenge, challenge.UserId);

        Assert.Equal(ResultStatus.Ok, result.Status);
    }

    private static UserAuthChallenge BuildChallenge(
        ChallengePurpose purpose,
        string? targetEmail = null,
        string? targetPhoneE164 = null)
    {
        var user = new User
        {
            Id = Guid.NewGuid(),
            Name = "policy-user",
            Email = "user@example.test",
            PhoneE164 = "+31612345678",
            PasswordHash = "hash",
            Role = "client",
            IsActive = true,
            IsVerified = true,
            MustChangePassword = false,
            CreatedAt = DateTime.UnixEpoch,
            UpdatedAt = DateTime.UnixEpoch
        };

        return new UserAuthChallenge
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            User = user,
            Purpose = purpose.ToValue(),
            TargetEmail = targetEmail,
            TargetPhoneE164 = targetPhoneE164,
            CodeHash = [1, 2, 3],
            AttemptCount = 0,
            ResendCount = 0,
            CreatedAt = DateTime.UnixEpoch,
            ExpiresAt = DateTime.UnixEpoch.AddMinutes(5)
        };
    }
}
