using System.Security.Claims;
using System.Text.Encodings.Web;
using Lumenary.Application.Common.Options;
using Lumenary.Persistence;
using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Lumenary.Infrastructure.Auth.Sessions;

public sealed class SessionAuthenticationHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder,
    IOptions<AuthOptions> authOptions)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    private readonly AuthOptions _authOptions = authOptions.Value;

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var token = GetTokenFromRequest();
        if (string.IsNullOrWhiteSpace(token))
            return AuthenticateResult.NoResult();

        var secret = _authOptions.SessionTokenKey;
        if (!SessionTokenUtilities.TryComputeHash(token, secret, out var tokenHash))
            return AuthenticateResult.Fail("Invalid session token.");

        var dbContext = Context.RequestServices.GetRequiredService<AppDbContext>();
        var session = await dbContext.Sessions
            .AsNoTracking()
            .Include(s => s.User)
            .FirstOrDefaultAsync(s => s.SessionTokenHash.SequenceEqual(tokenHash));

        if (session == null)
            return AuthenticateResult.Fail("Invalid session.");

        var now = DateTime.UtcNow;
        if (session.RevokedAt != null || session.ExpiresAt <= now)
            return AuthenticateResult.Fail("Session expired.");

        if (!session.User.IsActive)
            return AuthenticateResult.Fail("User inactive.");

        if (!session.User.IsVerified)
            return AuthenticateResult.Fail("User unverified.");

        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, session.UserId.ToString()),
            new Claim(ClaimTypes.Role, session.User.Role),
            new Claim(ClaimTypes.Sid, session.Id.ToString())
        };

        var identity = new ClaimsIdentity(claims, SessionAuthenticationDefaults.Scheme);
        var principal = new ClaimsPrincipal(identity);
        var ticket = new AuthenticationTicket(principal, SessionAuthenticationDefaults.Scheme);

        return AuthenticateResult.Success(ticket);
    }

    private string? GetTokenFromRequest()
    {
        var authorization = Request.Headers.Authorization.ToString();
        if (!string.IsNullOrWhiteSpace(authorization) &&
            authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            var bearerToken = authorization["Bearer ".Length..].Trim();
            if (!string.IsNullOrWhiteSpace(bearerToken))
                return bearerToken;
        }

        var cookieName = _authOptions.CookieName;
        if (!string.IsNullOrWhiteSpace(cookieName) &&
            Request.Cookies.TryGetValue(cookieName, out var cookieToken) &&
            !string.IsNullOrWhiteSpace(cookieToken))
            return cookieToken;

        return null;
    }
}
