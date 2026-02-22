using Lumenary.Api.Common.Validation;
using Lumenary.Common.Validation;

namespace Lumenary.Api.Tests.Common.Validation;

public sealed class PasswordStrengthAttributeTests
{
    private static readonly PasswordStrengthAttribute Sut = new();

    [Fact]
    public void IsValid_WhenValueIsNull_ThenReturnsFalse()
    {
        Assert.False(Sut.IsValid(null));
    }

    [Fact]
    public void IsValid_WhenValueIsNotString_ThenReturnsFalse()
    {
        Assert.False(Sut.IsValid(12345));
    }

    [Fact]
    public void IsValid_WhenBelowMinimumLength_ThenReturnsFalse()
    {
        var tooShortPassword = "a" + new string('1', ValidationConstants.PasswordMinLength - 2);

        Assert.False(Sut.IsValid(tooShortPassword));
    }

    [Fact]
    public void IsValid_WhenOnlyLetters_ThenReturnsFalse()
    {
        var password = new string('a', ValidationConstants.PasswordMinLength);

        Assert.False(Sut.IsValid(password));
    }

    [Fact]
    public void IsValid_WhenOnlyDigits_ThenReturnsFalse()
    {
        var password = new string('1', ValidationConstants.PasswordMinLength);

        Assert.False(Sut.IsValid(password));
    }

    [Fact]
    public void IsValid_WhenContainsLettersAndDigitsAtMinimumLength_ThenReturnsTrue()
    {
        var password = $"a{new string('1', ValidationConstants.PasswordMinLength - 1)}";

        Assert.True(Sut.IsValid(password));
    }

    [Fact]
    public void IsValid_WhenContainsLettersDigitsAndSymbols_ThenReturnsTrue()
    {
        Assert.True(Sut.IsValid("Str0ng!Pass"));
    }
}
