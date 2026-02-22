using System.ComponentModel.DataAnnotations;
using Lumenary.Api.Common.Validation;
using Lumenary.Common.Validation;

namespace Lumenary.Api.Contracts.Auth;

public sealed record LoginRequest(
    [param: NotWhiteSpace, EmailAddress, StringLength(ValidationConstants.EmailMaxLength)] string Email,
    [param: NotWhiteSpace, StringLength(ValidationConstants.PasswordMaxLength)] string Password);
