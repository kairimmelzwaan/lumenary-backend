using Microsoft.EntityFrameworkCore;
using Lumenary.Persistence.Entities;

namespace Lumenary.Persistence;

public class AppDbContext : DbContext, IAppDbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options)
        : base(options)
    {
    }

    public DbSet<User> Users { get; set; } = null!;
    public DbSet<Session> Sessions { get; set; } = null!;
    public DbSet<Client> Clients { get; set; } = null!;
    public DbSet<UserAuthChallenge> UserAuthChallenges { get; set; } = null!;

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.HasPostgresExtension("citext");
        modelBuilder.ApplyConfigurationsFromAssembly(typeof(AppDbContext).Assembly);
    }

    public void ClearChangeTracker() => ChangeTracker.Clear();

    public bool UsesInMemoryProvider =>
        string.Equals(Database.ProviderName, "Microsoft.EntityFrameworkCore.InMemory", StringComparison.Ordinal);

    public bool IsUniqueConstraintViolation(DbUpdateException exception)
        => exception.IsUniqueConstraintViolation();
}
