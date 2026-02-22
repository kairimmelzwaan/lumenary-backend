namespace Lumenary.Api.Contracts.Account;

public sealed record AccountMeResponse(
    string Name,
    string Email,
    string PhoneE164,
    DateTime? DateOfBirth);
