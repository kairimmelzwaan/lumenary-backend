namespace Lumenary.Features.Auth.Models;

public sealed record ResendCodeRequest(Guid ChallengeId);

public sealed record ResendCodeResponse(
    Guid ChallengeId,
    string? Code);

public sealed record ChangeEmailCancelRequest(Guid ChallengeId);

public sealed record ChangeEmailRequest(string Email);

public sealed record ChangeEmailResponse(
    Guid ChallengeId,
    string? Code);

public sealed record ChangeEmailVerifyRequest(
    Guid ChallengeId,
    string Code);

public sealed record LoginRequest(
    string Email,
    string Password);

public sealed record LoginResponse(
    Guid ChallengeId,
    string? Code);

public sealed record LoginVerifyRequest(
    Guid ChallengeId,
    string Code);

public sealed record PasswordChangeRequest(
    string CurrentPassword,
    string NewPassword);

public sealed record PasswordResetRequest(string Email);

public sealed record PasswordResetResponse(
    Guid ChallengeId,
    string? Code);

public sealed record PasswordResetVerifyRequest(
    Guid ChallengeId,
    string Code);

public sealed record PasswordResetChangeRequest(
    Guid ChallengeId,
    string NewPassword);

public sealed record ChangePhoneCancelRequest(Guid ChallengeId);

public sealed record ChangePhoneRequest(string PhoneE164);

public sealed record ChangePhoneResponse(
    Guid ChallengeId,
    string? Code);

public sealed record ChangePhoneVerifyRequest(
    Guid ChallengeId,
    string Code);

public sealed record RegisterRequest(
    string Name,
    string Email,
    string Password,
    string PhoneE164,
    DateTime DateOfBirth);

public sealed record RegisterResponse(
    Guid ChallengeId,
    string? Code);

public sealed record RegisterVerifyRequest(
    Guid ChallengeId,
    string Code);

public sealed record SessionResponse(
    DateTime CreatedAt,
    DateTime LastSeenAt,
    DateTime ExpiresAt,
    string? UserAgent,
    string? IpAddress);

public sealed record SessionsOverviewResponse(
    DateTime? LastLoginAt,
    string? LastLoginUserAgent,
    string? LastLoginIpAddress,
    IReadOnlyList<SessionResponse> Sessions);
