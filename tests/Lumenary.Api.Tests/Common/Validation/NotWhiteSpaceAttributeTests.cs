using Lumenary.Api.Common.Validation;

namespace Lumenary.Api.Tests.Common.Validation;

public sealed class NotWhiteSpaceAttributeTests
{
    private static readonly NotWhiteSpaceAttribute Sut = new();

    [Fact]
    public void IsValid_WhenValueIsNull_ThenReturnsFalse()
    {
        Assert.False(Sut.IsValid(null));
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("\t\r\n")]
    public void IsValid_WhenValueIsWhitespace_ThenReturnsFalse(string value)
    {
        Assert.False(Sut.IsValid(value));
    }

    [Theory]
    [InlineData("x")]
    [InlineData("  value  ")]
    public void IsValid_WhenValueContainsNonWhitespaceText_ThenReturnsTrue(string value)
    {
        Assert.True(Sut.IsValid(value));
    }

    [Fact]
    public void IsValid_WhenValueIsNonStringObject_ThenReturnsTrue()
    {
        Assert.True(Sut.IsValid(123));
    }
}
