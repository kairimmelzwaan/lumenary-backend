using Lumenary.Persistence.Entities;

namespace Lumenary.Features.Auth.Services;

public interface ISessionService
{
    Task CreateSessionAndSetCookieAsync(User user, DateTime now, CancellationToken cancellationToken);
    void ClearSessionCookie();
}
