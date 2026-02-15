using System.ComponentModel.DataAnnotations;
using backend.Validation;

namespace backend.Dtos;

public sealed record PasswordChangeRequest(
    [param: NotWhiteSpace, StringLength(ValidationConstants.PasswordMaxLength)] string CurrentPassword,
    [param: NotWhiteSpace, PasswordStrength, StringLength(ValidationConstants.PasswordMaxLength)] string NewPassword);
