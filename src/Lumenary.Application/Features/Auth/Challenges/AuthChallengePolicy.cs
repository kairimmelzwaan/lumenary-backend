namespace Lumenary.Features.Auth.Challenges;

public static class AuthChallengePolicy
{
    public const int MaxAttempts = 3;
    public const int MaxResends = 3;
    public const int ResendCooldownSeconds = 30;
    public const int MaxLifetimeMinutes = 30;
}
