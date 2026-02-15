namespace backend.Auth.Options;

public sealed class AuthOptions
{
    public string? SessionTokenKey { get; set; }
    public string? VerificationCodeKey { get; set; }
    public bool ReturnDebugCodes { get; set; }
    public int LoginCodeTtlMinutes { get; set; } = 5;
    public int SessionTtlDays { get; set; } = 14;
    public string CookieName { get; set; } = "lumenary_session";
    public int ChallengeCleanupIntervalMinutes { get; set; } = 30;
    public int ChallengeRetentionDays { get; set; } = 7;
    public RateLimitOptions RateLimit { get; set; } = new();
    public IdentifierRateLimitOptions IdentifierRateLimit { get; set; } = new();

    public sealed class RateLimitOptions
    {
        public int PermitLimit { get; set; } = 10;
        public int WindowSeconds { get; set; } = 60;
        public int QueueLimit { get; set; } = 0;
    }

    public sealed class IdentifierRateLimitOptions
    {
        public int PermitLimit { get; set; } = 10;
        public int WindowSeconds { get; set; } = 60;
        public int QueueLimit { get; set; } = 0;
    }
}
