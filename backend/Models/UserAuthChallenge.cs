namespace backend.Models;

public class UserAuthChallenge
{
    public Guid Id { get; set; }
    public Guid UserId { get; set; }
    public string Purpose { get; set; } = null!;
    public string? TargetEmail { get; set; }
    public string? TargetPhoneE164 { get; set; }
    public byte[] CodeHash { get; set; } = null!;
    public int AttemptCount { get; set; }
    public int ResendCount { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime? LastResentAt { get; set; }
    public DateTime ExpiresAt { get; set; }
    public DateTime? VerifiedAt { get; set; }

    public User User { get; set; } = null!;
}
