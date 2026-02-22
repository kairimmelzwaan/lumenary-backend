using Lumenary.Api.Common.Validation;

namespace Lumenary.Api.Tests.Common.Validation;

public sealed class NotWhiteSpaceIfProvidedAttributeTests
{
    private static readonly NotWhiteSpaceIfProvidedAttribute Sut = new();

    [Fact]
    public void IsValid_WhenValueIsNull_ThenReturnsTrue()
    {
        Assert.True(Sut.IsValid(null));
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("\t")]
    public void IsValid_WhenValueIsWhitespace_ThenReturnsFalse(string value)
    {
        Assert.False(Sut.IsValid(value));
    }

    [Theory]
    [InlineData("name")]
    [InlineData("  name  ")]
    public void IsValid_WhenValueContainsNonWhitespaceText_ThenReturnsTrue(string value)
    {
        Assert.True(Sut.IsValid(value));
    }

    [Fact]
    public void IsValid_WhenValueIsNonStringObject_ThenReturnsFalse()
    {
        Assert.False(Sut.IsValid(123));
    }
}
