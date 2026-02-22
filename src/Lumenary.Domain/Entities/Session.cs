namespace Lumenary.Persistence.Entities;

public class Session
{
    public Guid Id { get; set; }
    public Guid UserId { get; set; }
    public byte[] SessionTokenHash { get; set; } = null!;
    public string? UserAgent { get; set; }
    public string? IpAddress { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime LastSeenAt { get; set; }
    public DateTime ExpiresAt { get; set; }
    public DateTime? RevokedAt { get; set; }
    public Guid? ReplacedBySessionId { get; set; }

    public User User { get; set; } = null!;
}
