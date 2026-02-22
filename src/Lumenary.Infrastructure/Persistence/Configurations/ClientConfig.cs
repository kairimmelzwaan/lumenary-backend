using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Lumenary.Persistence.Entities;

namespace Lumenary.Persistence.Configurations;

public class ClientConfig : IEntityTypeConfiguration<Client>
{
    public void Configure(EntityTypeBuilder<Client> builder)
    {
        builder.ToTable("clients");

        builder.HasKey(c => c.Id);

        builder.Property(c => c.Id)
            .HasDefaultValueSql("gen_random_uuid()");

        builder.Property(c => c.UserId)
            .IsRequired();

        builder.HasIndex(c => c.UserId)
            .IsUnique();

        builder.Property(c => c.TherapistUserId)
            .IsRequired();

        builder.Property(c => c.DateOfBirth)
            .HasColumnType("date")
            .IsRequired();

        builder.Property(c => c.CreatedAt)
            .HasColumnType("timestamptz")
            .HasDefaultValueSql("now()");

        builder.Property(c => c.UpdatedAt)
            .HasColumnType("timestamptz")
            .HasDefaultValueSql("now()");

        builder.HasOne(c => c.User)
            .WithOne(u => u.ClientProfile)
            .HasForeignKey<Client>(c => c.UserId)
            .OnDelete(DeleteBehavior.Cascade);

        builder.HasOne(c => c.TherapistUser)
            .WithMany(u => u.TherapistClients)
            .HasForeignKey(c => c.TherapistUserId)
            .OnDelete(DeleteBehavior.Restrict);
    }
}
