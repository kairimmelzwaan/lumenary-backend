using Lumenary.Application.Common.Options;
using Lumenary.Infrastructure.Auth.Sessions;
using Lumenary.Persistence;
using Lumenary.Persistence.Entities;
using Lumenary.Common.Http;
using Microsoft.Extensions.Options;

namespace Lumenary.Features.Auth.Services;

public sealed class SessionService : ISessionService
{
    private const int MaxUserAgentLength = 512;
    private const int MaxIpAddressLength = 64;

    private readonly IAppDbContext _dbContext;
    private readonly AuthOptions _options;
    private readonly IRequestMetadataAccessor _requestMetadataAccessor;
    private readonly ISessionCookieWriter _sessionCookieWriter;

    public SessionService(
        IAppDbContext dbContext,
        IOptions<AuthOptions> options,
        IRequestMetadataAccessor requestMetadataAccessor,
        ISessionCookieWriter sessionCookieWriter)
    {
        _dbContext = dbContext;
        _options = options.Value;
        _requestMetadataAccessor = requestMetadataAccessor;
        _sessionCookieWriter = sessionCookieWriter;
    }

    public async Task CreateSessionAndSetCookieAsync(User user, DateTime now, CancellationToken cancellationToken)
    {
        var token = SessionTokenUtilities.CreateToken(_options.SessionTokenKey, out var tokenHash);
        var expiresAt = now.AddDays(_options.SessionTtlDays);
        var userAgent = Clamp(_requestMetadataAccessor.UserAgent, MaxUserAgentLength);
        var ipAddress = Clamp(_requestMetadataAccessor.IpAddress, MaxIpAddressLength);

        var session = new Session
        {
            UserId = user.Id,
            SessionTokenHash = tokenHash,
            UserAgent = userAgent,
            IpAddress = ipAddress,
            CreatedAt = now,
            LastSeenAt = now,
            ExpiresAt = expiresAt
        };

        _dbContext.Sessions.Add(session);
        await _dbContext.SaveChangesAsync(cancellationToken);

        _sessionCookieWriter.WriteSessionCookie(token, expiresAt);
    }

    public void ClearSessionCookie()
    {
        _sessionCookieWriter.ClearSessionCookie();
    }

    private static string? Clamp(string? value, int maxLength)
    {
        if (string.IsNullOrEmpty(value) || value.Length <= maxLength)
            return value;

        return value[..maxLength];
    }
}
