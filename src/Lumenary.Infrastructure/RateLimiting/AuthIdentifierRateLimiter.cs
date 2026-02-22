using System.Threading.RateLimiting;
using Lumenary.Application.Common.Options;
using Microsoft.Extensions.Options;

namespace Lumenary.Infrastructure.RateLimiting;

public sealed class AuthIdentifierRateLimiter : IAsyncDisposable
{
    private readonly PartitionedRateLimiter<string> _limiter;

    public AuthIdentifierRateLimiter(IOptions<AuthOptions> options)
    {
        var rateLimit = options.Value.IdentifierRateLimit;

        _limiter = PartitionedRateLimiter.Create<string, string>(key =>
            RateLimitPartition.GetFixedWindowLimiter(
                key,
                _ => new FixedWindowRateLimiterOptions
                {
                    PermitLimit = rateLimit.PermitLimit,
                    Window = TimeSpan.FromSeconds(rateLimit.WindowSeconds),
                    QueueLimit = rateLimit.QueueLimit,
                    QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                    AutoReplenishment = true
                }));
    }

    public ValueTask<RateLimitLease> AcquireAsync(string key, CancellationToken cancellationToken)
        => _limiter.AcquireAsync(key, 1, cancellationToken);

    public ValueTask DisposeAsync() => _limiter.DisposeAsync();
}
