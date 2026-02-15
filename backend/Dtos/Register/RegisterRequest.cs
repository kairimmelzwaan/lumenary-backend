using System.ComponentModel.DataAnnotations;
using backend.Validation;

namespace backend.Dtos;

public sealed record RegisterRequest(
    [param: NotWhiteSpace, StringLength(ValidationConstants.NameMaxLength)] string Name,
    [param: NotWhiteSpace, EmailAddress, StringLength(ValidationConstants.EmailMaxLength)] string Email,
    [param: NotWhiteSpace, PasswordStrength, StringLength(ValidationConstants.PasswordMaxLength)] string Password,
    [param: NotWhiteSpace, PhoneE164] string PhoneE164,
    [param: DateInPast] DateTime DateOfBirth);
