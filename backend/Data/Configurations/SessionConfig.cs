using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using backend.Models;

namespace backend.Data.Configurations;

public class SessionConfig : IEntityTypeConfiguration<Session>
{
    public void Configure(EntityTypeBuilder<Session> builder)
    {
        builder.ToTable("sessions");

        builder.HasKey(u => u.Id);

        builder.Property(u => u.Id)
            .HasDefaultValueSql("gen_random_uuid()");

        builder.Property(u => u.UserId)
            .IsRequired();

        builder.Property(u => u.SessionTokenHash)
            .HasColumnType("bytea")
            .IsRequired();

        builder.Property(u => u.UserAgent)
            .HasMaxLength(512);

        builder.Property(u => u.IpAddress)
            .HasMaxLength(64);

        builder.Property(u => u.CreatedAt)
            .HasColumnType("timestamptz")
            .HasDefaultValueSql("now()");
        builder.Property(u => u.LastSeenAt)
            .HasColumnType("timestamptz")
            .HasDefaultValueSql("now()");
        builder.Property(u => u.ExpiresAt)
            .HasColumnType("timestamptz")
            .HasDefaultValueSql("now() + interval '1 week'");

        builder.Property(u => u.RevokedAt)
            .HasColumnType("timestamptz");

        builder.Property(u => u.ReplacedBySessionId);

        builder.HasIndex(s => s.SessionTokenHash)
            .IsUnique();

        builder.HasIndex(s => new { s.UserId, s.ExpiresAt });

        builder.HasOne(s => s.User)
            .WithMany(u => u.Sessions)
            .HasForeignKey(s => s.UserId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}
