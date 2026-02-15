using backend.Data;
using backend.Models;
using Microsoft.EntityFrameworkCore;

namespace backend.Services.Users;

public sealed class UserLookupService(AppDbContext dbContext) : IUserLookupService
{
    public async Task<User?> GetActiveUserAsync(
        Guid userId,
        UserTrackingMode trackingMode,
        CancellationToken cancellationToken)
    {
        var query = dbContext.Users
            .Where(user => user.Id == userId && user.IsActive);

        if (trackingMode == UserTrackingMode.ReadOnly)
        {
            query = query.AsNoTracking();
        }

        return await query.FirstOrDefaultAsync(cancellationToken);
    }

    public async Task<User?> GetActiveUserWithClientProfileAsync(
        Guid userId,
        UserTrackingMode trackingMode,
        CancellationToken cancellationToken)
    {
        var query = dbContext.Users
            .Include(user => user.ClientProfile)
            .Where(user => user.Id == userId && user.IsActive);

        if (trackingMode == UserTrackingMode.ReadOnly)
        {
            query = query.AsNoTracking();
        }

        return await query.FirstOrDefaultAsync(cancellationToken);
    }
}