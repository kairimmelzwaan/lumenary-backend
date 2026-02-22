using Lumenary.Api.Common.Validation;

namespace Lumenary.Api.Tests.Common.Validation;

public sealed class PhoneE164AttributeTests
{
    private static readonly PhoneE164Attribute Sut = new();

    [Fact]
    public void IsValid_WhenValueIsNull_ThenReturnsFalse()
    {
        Assert.False(Sut.IsValid(null));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void IsValid_WhenValueIsWhitespace_ThenReturnsFalse(string value)
    {
        Assert.False(Sut.IsValid(value));
    }

    [Theory]
    [InlineData("+31612345678")]
    [InlineData("00 31 6-1234-5678")]
    public void IsValid_WhenValueNormalizesToValidE164_ThenReturnsTrue(string value)
    {
        Assert.True(Sut.IsValid(value));
    }

    [Theory]
    [InlineData("31612345678")]
    [InlineData("+0123456789")]
    [InlineData("+1234567890123456")]
    public void IsValid_WhenValueDoesNotMatchE164_ThenReturnsFalse(string value)
    {
        Assert.False(Sut.IsValid(value));
    }

    [Fact]
    public void IsValid_WhenValueIsNotString_ThenReturnsFalse()
    {
        Assert.False(Sut.IsValid(123));
    }
}
