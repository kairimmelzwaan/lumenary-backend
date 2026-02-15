using Microsoft.AspNetCore.Authorization;

namespace backend.Auth.AnonymousOnly;

public sealed class AnonymousOnlyAttribute : AuthorizeAttribute
{
    public const string PolicyName = "AnonymousOnly";

    public AnonymousOnlyAttribute()
        => Policy = PolicyName;
}
