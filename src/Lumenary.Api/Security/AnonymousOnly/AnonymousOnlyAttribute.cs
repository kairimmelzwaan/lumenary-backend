using Microsoft.AspNetCore.Authorization;

namespace Lumenary.Api.Security.AnonymousOnly;

public sealed class AnonymousOnlyAttribute : AuthorizeAttribute
{
    public const string PolicyName = "AnonymousOnly";

    public AnonymousOnlyAttribute()
        => Policy = PolicyName;
}
