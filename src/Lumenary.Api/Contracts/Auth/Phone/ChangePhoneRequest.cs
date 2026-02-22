using Lumenary.Api.Common.Validation;
using Lumenary.Common.Validation;

namespace Lumenary.Api.Contracts.Auth;

public sealed record ChangePhoneRequest(
    [param: NotWhiteSpace, PhoneE164] string PhoneE164);
