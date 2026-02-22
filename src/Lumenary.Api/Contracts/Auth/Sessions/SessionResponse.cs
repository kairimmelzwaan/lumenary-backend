namespace Lumenary.Api.Contracts.Auth;

public sealed record SessionResponse(
    DateTime CreatedAt,
    DateTime LastSeenAt,
    DateTime ExpiresAt,
    string? UserAgent,
    string? IpAddress);
