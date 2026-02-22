using Lumenary.Infrastructure.Security.Verification;

namespace Lumenary.Tests.Infrastructure.Security.Verification;

public sealed class VerificationCodeUtilitiesTests
{
    [Fact]
    public void CreateCode_WhenCalledWithoutLength_ThenReturnsSixNumericDigits()
    {
        var code = VerificationCodeUtilities.CreateCode();

        Assert.Equal(6, code.Length);
        Assert.All(code, ch => Assert.InRange(ch, '0', '9'));
    }

    [Fact]
    public void CreateCode_WhenCustomLengthProvided_ThenReturnsCodeWithRequestedLength()
    {
        var code = VerificationCodeUtilities.CreateCode(8);

        Assert.Equal(8, code.Length);
        Assert.All(code, ch => Assert.InRange(ch, '0', '9'));
    }

    [Fact]
    public void CreateCode_WhenLengthIsNonPositive_ThenThrowsArgumentOutOfRangeException()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => VerificationCodeUtilities.CreateCode(0));
    }

    [Fact]
    public void ComputeHash_WhenSecretProvided_ThenHashIsDeterministicAndDifferentFromNoSecretHash()
    {
        const string code = "123456";
        const string secret = "sum-32-character-long-secret-key";

        var withSecretA = VerificationCodeUtilities.ComputeHash(code, secret);
        var withSecretB = VerificationCodeUtilities.ComputeHash(code, secret);
        var withoutSecret = VerificationCodeUtilities.ComputeHash(code, null);

        Assert.True(withSecretA.SequenceEqual(withSecretB));
        Assert.False(withSecretA.SequenceEqual(withoutSecret));
        Assert.Equal(32, withSecretA.Length);
    }
}
