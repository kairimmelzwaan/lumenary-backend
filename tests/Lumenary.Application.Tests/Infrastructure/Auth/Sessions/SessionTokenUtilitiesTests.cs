using Lumenary.Infrastructure.Auth.Sessions;

namespace Lumenary.Tests.Infrastructure.Auth.Sessions;

public sealed class SessionTokenUtilitiesTests
{
    [Fact]
    public void CreateToken_WhenCalled_ThenTryComputeHashWithSameSecretMatchesGeneratedHash()
    {
        const string secret = "01234567890123456789012345678901";

        var token = SessionTokenUtilities.CreateToken(secret, out var generatedHash);
        var success = SessionTokenUtilities.TryComputeHash(token, secret, out var computedHash);

        Assert.True(success);
        Assert.True(generatedHash.SequenceEqual(computedHash));
    }

    [Fact]
    public void TryComputeHash_WhenTokenFormatIsInvalid_ThenReturnsFalseAndEmptyHash()
    {
        var success = SessionTokenUtilities.TryComputeHash("***invalid***", "secret", out var hash);

        Assert.False(success);
        Assert.Empty(hash);
    }

    [Fact]
    public void TryComputeHash_WhenSecretDiffers_ThenComputedHashChanges()
    {
        var token = SessionTokenUtilities.CreateToken("secret-a", out var hashWithSecretA);
        var success = SessionTokenUtilities.TryComputeHash(token, "secret-b", out var hashWithSecretB);

        Assert.True(success);
        Assert.False(hashWithSecretA.SequenceEqual(hashWithSecretB));
    }
}
