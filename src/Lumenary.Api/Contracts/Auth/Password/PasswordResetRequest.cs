using System.ComponentModel.DataAnnotations;
using Lumenary.Api.Common.Validation;
using Lumenary.Common.Validation;

namespace Lumenary.Api.Contracts.Auth;

public sealed record PasswordResetRequest(
    [param: NotWhiteSpace, EmailAddress, StringLength(ValidationConstants.EmailMaxLength)] string Email);
