using Microsoft.AspNetCore.Authorization;

namespace Lumenary.Api.Security.AnonymousOnly;

public sealed class AnonymousOnlyRequirement : IAuthorizationRequirement;
