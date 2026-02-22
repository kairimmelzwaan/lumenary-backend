namespace Lumenary.Common.Http;

public interface IRequestMetadataAccessor
{
    string UserAgent { get; }
    string? IpAddress { get; }
}
