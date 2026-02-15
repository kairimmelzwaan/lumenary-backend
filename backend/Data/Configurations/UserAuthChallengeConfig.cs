using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using backend.Models;

namespace backend.Data.Configurations;

public class UserAuthChallengeConfig : IEntityTypeConfiguration<UserAuthChallenge>
{
    public void Configure(EntityTypeBuilder<UserAuthChallenge> builder)
    {
        builder.ToTable("user_auth_challenges");

        builder.HasKey(c => c.Id);

        builder.Property(c => c.Id)
            .HasDefaultValueSql("gen_random_uuid()");

        builder.Property(c => c.UserId)
            .IsRequired();

        builder.Property(c => c.Purpose)
            .HasMaxLength(32)
            .IsRequired();

        builder.Property(c => c.TargetEmail)
            .HasColumnType("citext")
            .HasMaxLength(255);

        builder.Property(c => c.TargetPhoneE164)
            .HasMaxLength(20);

        builder.Property(c => c.CodeHash)
            .HasColumnType("bytea")
            .IsRequired();

        builder.Property(c => c.AttemptCount)
            .HasDefaultValue(0);

        builder.Property(c => c.ResendCount)
            .HasDefaultValue(0);

        builder.Property(c => c.CreatedAt)
            .HasColumnType("timestamptz")
            .HasDefaultValueSql("now()");

        builder.Property(c => c.LastResentAt)
            .HasColumnType("timestamptz");

        builder.Property(c => c.ExpiresAt)
            .HasColumnType("timestamptz")
            .IsRequired();

        builder.Property(c => c.VerifiedAt)
            .HasColumnType("timestamptz");

        builder.HasIndex(c => new { c.UserId, c.Purpose, c.ExpiresAt });

        builder.HasOne(c => c.User)
            .WithMany()
            .HasForeignKey(c => c.UserId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}
