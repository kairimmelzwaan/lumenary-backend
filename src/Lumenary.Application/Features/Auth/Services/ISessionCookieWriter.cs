namespace Lumenary.Features.Auth.Services;

public interface ISessionCookieWriter
{
    void WriteSessionCookie(string token, DateTime expiresAt);
    void ClearSessionCookie();
}
