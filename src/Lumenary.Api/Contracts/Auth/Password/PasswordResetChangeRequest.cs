using System.ComponentModel.DataAnnotations;
using Lumenary.Api.Common.Validation;
using Lumenary.Common.Validation;

namespace Lumenary.Api.Contracts.Auth;

public sealed record PasswordResetChangeRequest(
    [param: NotEmptyGuid] Guid ChallengeId,
    [param: NotWhiteSpace, PasswordStrength, StringLength(ValidationConstants.PasswordMaxLength)] string NewPassword);
