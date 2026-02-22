using System.Text.Json.Serialization;

namespace Lumenary.Api.Contracts.Auth;

public sealed record PasswordResetResponse(
    Guid ChallengeId,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Code);
