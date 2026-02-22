using Lumenary.Persistence.Entities;
using Microsoft.EntityFrameworkCore;

namespace Lumenary.Persistence;

public interface IAppDbContext
{
    DbSet<User> Users { get; }
    DbSet<Session> Sessions { get; }
    DbSet<Client> Clients { get; }
    DbSet<UserAuthChallenge> UserAuthChallenges { get; }

    Task<int> SaveChangesAsync(CancellationToken cancellationToken = default);
    void ClearChangeTracker();
    bool UsesInMemoryProvider { get; }
    bool IsUniqueConstraintViolation(DbUpdateException exception);
}
