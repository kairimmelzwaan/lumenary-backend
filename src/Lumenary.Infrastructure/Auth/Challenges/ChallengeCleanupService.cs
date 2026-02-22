using Lumenary.Application.Common.Options;
using Lumenary.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Lumenary.Infrastructure.Auth.Challenges;

public sealed class ChallengeCleanupService(
    IServiceScopeFactory scopeFactory,
    ILogger<ChallengeCleanupService> logger,
    IOptions<AuthOptions> options)
    : BackgroundService
{
    private readonly AuthOptions _options = options.Value;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var intervalMinutes = _options.ChallengeCleanupIntervalMinutes;
        if (intervalMinutes < 1)
            intervalMinutes = 30;

        var retentionDays = _options.ChallengeRetentionDays;
        if (retentionDays < 0)
            retentionDays = 0;

        using var timer = new PeriodicTimer(TimeSpan.FromMinutes(intervalMinutes));
        while (await timer.WaitForNextTickAsync(stoppingToken))
        {
            try
            {
                var now = DateTime.UtcNow;
                var retentionCutoff = now.AddDays(-retentionDays);

                using var scope = scopeFactory.CreateScope();
                var dbContext = scope.ServiceProvider.GetRequiredService<AppDbContext>();

                var deleted = await dbContext.UserAuthChallenges
                    .Where(c => c.ExpiresAt <= now ||
                                (c.VerifiedAt != null && c.VerifiedAt <= retentionCutoff))
                    .ExecuteDeleteAsync(stoppingToken);

                if (deleted > 0)
                    logger.LogInformation("Removed {Count} old challenges.", deleted);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Auth challenge cleanup failed.");
            }
        }
    }
}
