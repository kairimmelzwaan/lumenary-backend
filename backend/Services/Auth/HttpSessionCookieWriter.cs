using backend.Auth.Options;
using Microsoft.Extensions.Options;

namespace backend.Services.Auth;

public sealed class HttpSessionCookieWriter(IHttpContextAccessor httpContextAccessor, IOptions<AuthOptions> options)
    : ISessionCookieWriter
{
    private readonly AuthOptions _options = options.Value;

    public void WriteSessionCookie(string token, DateTime expiresAt)
    {
        var httpContext = httpContextAccessor.HttpContext
            ?? throw new InvalidOperationException("HttpContext is required to set session cookies.");

        var cookieOptions = new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Lax,
            Expires = expiresAt,
            IsEssential = true,
            Path = "/"
        };

        httpContext.Response.Cookies.Append(_options.CookieName, token, cookieOptions);
    }

    public void ClearSessionCookie()
    {
        var httpContext = httpContextAccessor.HttpContext
            ?? throw new InvalidOperationException("HttpContext is required to clear session cookies.");

        httpContext.Response.Cookies.Delete(_options.CookieName, new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Lax,
            IsEssential = true,
            Path = "/"
        });
    }
}
