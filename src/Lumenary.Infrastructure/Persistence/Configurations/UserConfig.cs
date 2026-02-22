using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Lumenary.Persistence.Entities;
using Lumenary.Domain.ValueObjects;
using Lumenary.Common.Validation;

namespace Lumenary.Persistence.Configurations;

public class UserConfig : IEntityTypeConfiguration<User>
{
    public void Configure(EntityTypeBuilder<User> builder)
    {
        builder.ToTable("users", table =>
        {
            var roles = string.Join("','", UserRoles.All);
            table.HasCheckConstraint(
                "CK_users_role",
                $"\"Role\" IN ('{roles}')");
        });

        builder.HasKey(u => u.Id);

        builder.Property(u => u.Id)
            .HasDefaultValueSql("gen_random_uuid()");

        builder.Property(u => u.Name)
            .HasMaxLength(ValidationConstants.NameMaxLength)
            .IsRequired();

        builder.Property(u => u.Email)
            .HasColumnType("citext")
            .HasMaxLength(ValidationConstants.EmailMaxLength)
            .IsRequired();

        builder.HasIndex(u => u.Email)
            .IsUnique();

        builder.Property(u => u.PendingEmail)
            .HasColumnType("citext")
            .HasMaxLength(ValidationConstants.EmailMaxLength);

        builder.Property(u => u.PendingEmailRequestedAt)
            .HasColumnType("timestamptz");

        builder.Property(u => u.PhoneE164)
            .HasMaxLength(20)
            .IsRequired();

        builder.HasIndex(u => u.PhoneE164)
            .IsUnique();

        builder.Property(u => u.PendingPhoneE164)
            .HasMaxLength(20);

        builder.Property(u => u.PendingPhoneRequestedAt)
            .HasColumnType("timestamptz");

        builder.Property(u => u.PasswordHash)
            .IsRequired();

        builder.Property(u => u.Role)
            .HasMaxLength(32)
            .IsRequired();

        builder.Property(u => u.MustChangePassword)
            .HasDefaultValue(false);

        builder.Property(u => u.IsVerified)
            .HasDefaultValue(false);

        builder.Property(u => u.IsActive)
            .HasDefaultValue(true);

        builder.Property(u => u.CreatedAt)
            .HasColumnType("timestamptz")
            .HasDefaultValueSql("now()");

        builder.Property(u => u.UpdatedAt)
            .HasColumnType("timestamptz")
            .HasDefaultValueSql("now()");

    }
}
