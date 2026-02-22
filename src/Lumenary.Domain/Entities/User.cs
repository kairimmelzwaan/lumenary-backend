namespace Lumenary.Persistence.Entities;

public class User
{
    public Guid Id { get; set; }
    public string Name { get; set; } = null!;
    public string Email { get; set; } = null!;
    public string? PendingEmail { get; set; }
    public DateTime? PendingEmailRequestedAt { get; set; }
    public string PhoneE164 { get; set; } = null!;
    public string? PendingPhoneE164 { get; set; }
    public DateTime? PendingPhoneRequestedAt { get; set; }
    public string PasswordHash { get; set; } = null!;
    public string Role { get; set; } = null!;
    public bool MustChangePassword { get; set; }
    public bool IsVerified { get; set; }
    public bool IsActive { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }

    public ICollection<Session> Sessions { get; set; } = new List<Session>();
    public Client? ClientProfile { get; set; }
    public ICollection<Client> TherapistClients { get; set; } = new List<Client>();
}
