using Lumenary.Application.Common.Options;
using Microsoft.Extensions.Options;

namespace Lumenary.Infrastructure.Security.Csrf;

public sealed class CsrfOriginValidationMiddleware(
    RequestDelegate next,
    IOptions<AuthOptions> options,
    ILogger<CsrfOriginValidationMiddleware> logger)
{
    private static readonly HashSet<string> SafeMethods =
    [
        HttpMethods.Get,
        HttpMethods.Head,
        HttpMethods.Options,
        HttpMethods.Trace
    ];

    private readonly AuthOptions _options = options.Value;
    private readonly HashSet<string> _allowedOrigins = BuildAllowedOrigins(options.Value.CsrfAllowedOrigins);

    public async Task InvokeAsync(HttpContext context)
    {
        if (SafeMethods.Contains(context.Request.Method))
        {
            await next(context);
            return;
        }

        var cookieName = _options.CookieName;
        if (string.IsNullOrWhiteSpace(cookieName) || !context.Request.Cookies.ContainsKey(cookieName))
        {
            await next(context);
            return;
        }

        if (!TryGetOrigin(context.Request, out var requestOrigin))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            return;
        }

        if (IsSameOrigin(context, requestOrigin) || _allowedOrigins.Contains(requestOrigin))
        {
            await next(context);
            return;
        }

        logger.LogWarning(
            "Rejected potential CSRF request from origin {Origin} for {Method} {Path}",
            requestOrigin,
            context.Request.Method,
            context.Request.Path);

        context.Response.StatusCode = StatusCodes.Status403Forbidden;
    }

    private static bool TryGetOrigin(HttpRequest request, out string origin)
    {
        if (TryParseOriginHeader(request.Headers.Origin.ToString(), out origin))
            return true;

        return TryParseOriginHeader(request.Headers.Referer.ToString(), out origin);
    }

    private static bool TryParseOriginHeader(string? value, out string origin)
    {
        origin = string.Empty;
        if (string.IsNullOrWhiteSpace(value) || string.Equals(value, "null", StringComparison.OrdinalIgnoreCase))
            return false;

        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri))
            return false;

        if (!string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
            return false;

        origin = NormalizeOrigin(uri.GetLeftPart(UriPartial.Authority));
        return true;
    }

    private static bool IsSameOrigin(HttpContext context, string origin)
    {
        var currentOrigin = NormalizeOrigin($"{context.Request.Scheme}://{context.Request.Host.Value}");
        return string.Equals(origin, currentOrigin, StringComparison.OrdinalIgnoreCase);
    }

    private static HashSet<string> BuildAllowedOrigins(IEnumerable<string> origins)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var origin in origins)
        {
            if (!Uri.TryCreate(origin, UriKind.Absolute, out var uri))
                continue;

            if (!string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
                continue;

            set.Add(NormalizeOrigin(uri.GetLeftPart(UriPartial.Authority)));
        }

        return set;
    }

    private static string NormalizeOrigin(string origin)
        => origin.Trim().TrimEnd('/');
}
