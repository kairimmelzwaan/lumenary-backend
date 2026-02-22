using Lumenary.Api.Common.Validation;
using Lumenary.Common.Validation;

namespace Lumenary.Api.Tests.Common.Validation;

public sealed class VerificationCodeAttributeTests
{
    private static readonly VerificationCodeAttribute Sut = new();

    [Fact]
    public void IsValid_WhenValueIsNull_ThenReturnsFalse()
    {
        Assert.False(Sut.IsValid(null));
    }

    [Fact]
    public void IsValid_WhenValueIsNotString_ThenReturnsFalse()
    {
        Assert.False(Sut.IsValid(123456));
    }

    [Fact]
    public void IsValid_WhenCodeLengthIsIncorrect_ThenReturnsFalse()
    {
        var shortCode = new string('1', ValidationConstants.VerificationCodeLength - 1);

        Assert.False(Sut.IsValid(shortCode));
    }

    [Fact]
    public void IsValid_WhenCodeContainsNonDigit_ThenReturnsFalse()
    {
        var code = $"12A{new string('3', ValidationConstants.VerificationCodeLength - 3)}";

        Assert.False(Sut.IsValid(code));
    }

    [Fact]
    public void IsValid_WhenCodeIsDigitsWithExactLength_ThenReturnsTrue()
    {
        var code = new string('7', ValidationConstants.VerificationCodeLength);

        Assert.True(Sut.IsValid(code));
    }
}
