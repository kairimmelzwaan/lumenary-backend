using System.ComponentModel.DataAnnotations;
using Lumenary.Api.Common.Validation;
using Lumenary.Common.Validation;

namespace Lumenary.Api.Contracts.Account;

public sealed record UpdateProfileRequest(
    [param: NotWhiteSpaceIfProvided, StringLength(ValidationConstants.NameMaxLength)] string? Name,
    [param: DateInPastIfProvided] DateTime? DateOfBirth);
