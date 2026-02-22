using System.ComponentModel.DataAnnotations;
using Lumenary.Api.Common.Validation;
using Lumenary.Common.Validation;

namespace Lumenary.Api.Contracts.Auth;

public sealed record PasswordChangeRequest(
    [param: NotWhiteSpace, StringLength(ValidationConstants.PasswordMaxLength)] string CurrentPassword,
    [param: NotWhiteSpace, PasswordStrength, StringLength(ValidationConstants.PasswordMaxLength)] string NewPassword);
