using System.Text.Json.Serialization;

namespace Lumenary.Api.Contracts.Auth;

public sealed record ChangePhoneResponse(
    Guid ChallengeId,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Code);
