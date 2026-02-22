using Lumenary.Common.Http;

namespace Lumenary.Infrastructure.Http;

public sealed class HttpRequestMetadataAccessor : IRequestMetadataAccessor
{
    private readonly IHttpContextAccessor _httpContextAccessor;

    public HttpRequestMetadataAccessor(IHttpContextAccessor httpContextAccessor)
    {
        _httpContextAccessor = httpContextAccessor;
    }

    public string UserAgent => _httpContextAccessor.HttpContext?.Request.Headers.UserAgent.ToString() ?? string.Empty;

    public string? IpAddress => _httpContextAccessor.HttpContext?.Connection.RemoteIpAddress?.ToString();
}
