namespace Lumenary.Features.Account.Models;

public sealed record AccountMeResponse(
    string Name,
    string Email,
    string PhoneE164,
    DateTime? DateOfBirth);

public sealed record UpdateProfileRequest(
    string? Name,
    DateTime? DateOfBirth);
