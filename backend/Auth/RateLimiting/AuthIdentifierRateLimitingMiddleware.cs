using System.Text;
using System.Text.Json;
using backend.Auth.Identity;
using Microsoft.AspNetCore.RateLimiting;

namespace backend.Auth.RateLimiting;

public sealed class AuthIdentifierRateLimitingMiddleware(
    RequestDelegate next,
    AuthIdentifierRateLimiter rateLimiter)
{
    private const int MaxBodySizeBytes = 32 * 1024;
    private const string AuthRateLimitPolicy = "Auth";

    public async Task InvokeAsync(HttpContext context)
    {
        var endpoint = context.GetEndpoint();
        var rateLimit = endpoint?.Metadata.GetMetadata<EnableRateLimitingAttribute>();

        if (rateLimit == null ||
            !string.Equals(rateLimit.PolicyName, AuthRateLimitPolicy, StringComparison.Ordinal))
        {
            await next(context);
            return;
        }

        var identifier = await TryGetIdentifierAsync(context, context.RequestAborted);
        if (string.IsNullOrWhiteSpace(identifier))
        {
            await next(context);
            return;
        }

        var key = $"{context.Request.Path}:{identifier}";
        using var lease = await rateLimiter.AcquireAsync(key, context.RequestAborted);

        if (lease.IsAcquired)
        {
            await next(context);
            return;
        }

        context.Response.StatusCode = StatusCodes.Status429TooManyRequests;
    }

    private static async Task<string?> TryGetIdentifierAsync(
        HttpContext context,
        CancellationToken cancellationToken)
    {
        var request = context.Request;

        if (TryGetQueryIdentifier(request.Query, out var queryIdentifier))
            return queryIdentifier;

        if (!IsJsonContentType(request))
            return null;

        if (request.ContentLength.HasValue && request.ContentLength.Value > MaxBodySizeBytes)
            return null;

        request.EnableBuffering();

        string body;
        using (var reader = new StreamReader(request.Body, Encoding.UTF8, leaveOpen: true))
        {
            body = await reader.ReadToEndAsync(cancellationToken);
        }

        request.Body.Position = 0;

        if (string.IsNullOrWhiteSpace(body))
            return null;

        try
        {
            using var document = JsonDocument.Parse(body);
            if (document.RootElement.ValueKind != JsonValueKind.Object)
                return null;

            var root = document.RootElement;

            if (TryGetStringProperty(root, "email", out var email))
                return IdentifierNormalization.NormalizeEmail(email);

            if (TryGetStringProperty(root, "phoneE164", out var phone))
                return IdentifierNormalization.NormalizePhoneE164(phone);

            if (TryGetGuidProperty(root, "challengeId", out var challengeId))
                return challengeId.ToString();
        }
        catch (JsonException)
        {
            return null;
        }

        return null;
    }

    private static bool TryGetQueryIdentifier(IQueryCollection query, out string? identifier)
    {
        if (TryGetQueryValue(query, "email", out var email))
        {
            identifier = IdentifierNormalization.NormalizeEmail(email);
            return true;
        }

        if (TryGetQueryValue(query, "phoneE164", out var phone))
        {
            identifier = IdentifierNormalization.NormalizePhoneE164(phone);
            return true;
        }

        if (TryGetQueryValue(query, "challengeId", out var challengeIdValue) &&
            Guid.TryParse(challengeIdValue, out var challengeId))
        {
            identifier = challengeId.ToString();
            return true;
        }

        identifier = null;
        return false;
    }

    private static bool TryGetQueryValue(IQueryCollection query, string key, out string value)
    {
        if (query.TryGetValue(key, out var values) && values.Count > 0)
        {
            value = values[0];
            return true;
        }

        foreach (var pair in query)
        {
            if (!string.Equals(pair.Key, key, StringComparison.OrdinalIgnoreCase))
                continue;

            if (pair.Value.Count == 0)
                break;

            value = pair.Value[0];
            return true;
        }

        value = string.Empty;
        return false;
    }

    private static bool TryGetStringProperty(JsonElement root, string name, out string value)
    {
        foreach (var property in root.EnumerateObject())
        {
            if (!string.Equals(property.Name, name, StringComparison.OrdinalIgnoreCase))
                continue;

            if (property.Value.ValueKind == JsonValueKind.String)
            {
                value = property.Value.GetString() ?? string.Empty;
                return !string.IsNullOrWhiteSpace(value);
            }
        }

        value = string.Empty;
        return false;
    }

    private static bool TryGetGuidProperty(JsonElement root, string name, out Guid value)
    {
        foreach (var property in root.EnumerateObject())
        {
            if (!string.Equals(property.Name, name, StringComparison.OrdinalIgnoreCase))
                continue;

            if (property.Value.ValueKind == JsonValueKind.String &&
                Guid.TryParse(property.Value.GetString(), out value))
                return true;
        }

        value = Guid.Empty;
        return false;
    }

    private static bool IsJsonContentType(HttpRequest request)
    {
        var contentType = request.ContentType;
        if (string.IsNullOrWhiteSpace(contentType))
            return false;

        return contentType.Contains("json", StringComparison.OrdinalIgnoreCase);
    }
}
