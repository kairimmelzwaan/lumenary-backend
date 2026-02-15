using System.Text.Json.Serialization;

namespace backend.Dtos;

public sealed record LoginResponse(
    Guid ChallengeId,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Code);
