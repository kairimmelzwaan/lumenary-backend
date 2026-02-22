namespace Lumenary.Persistence.Entities;

public class Client
{
    public Guid Id { get; set; }
    public Guid UserId { get; set; }
    public Guid TherapistUserId { get; set; }
    public DateTime DateOfBirth { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }

    public User TherapistUser { get; set; } = null!;
    public User User { get; set; } = null!;
}
