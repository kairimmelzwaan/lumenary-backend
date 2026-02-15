using System.ComponentModel.DataAnnotations;
using backend.Validation;

namespace backend.Dtos;

public sealed record PasswordResetVerifyRequest(
    [param: NotEmptyGuid] Guid ChallengeId,
    [param: VerificationCode] string Code,
    [param: NotWhiteSpace, PasswordStrength, StringLength(ValidationConstants.PasswordMaxLength)] string NewPassword);
