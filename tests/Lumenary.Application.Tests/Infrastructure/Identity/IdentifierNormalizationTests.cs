using Lumenary.Infrastructure.Identity;

namespace Lumenary.Tests.Infrastructure.Identity;

public sealed class IdentifierNormalizationTests
{
    [Fact]
    public void NormalizeEmail_WhenEmailHasWhitespaceAndUppercase_ThenReturnsTrimmedLowercaseValue()
    {
        var result = IdentifierNormalization.NormalizeEmail("  User.Name+Tag@Example.COM  ");

        Assert.Equal("user.name+tag@example.com", result);
    }

    [Fact]
    public void NormalizePhoneE164_WhenPhoneUsesInternationalPrefixAndSeparators_ThenNormalizesToDigitsWithLeadingPlus()
    {
        var result = IdentifierNormalization.NormalizePhoneE164("00 31 (0)6-12 34 56 78");

        Assert.Equal("+310612345678", result);
    }

    [Fact]
    public void NormalizePhoneE164_WhenInputContainsMultiplePlusCharacters_ThenKeepsOnlyLeadingPlus()
    {
        var result = IdentifierNormalization.NormalizePhoneE164("++31+6-12+34");

        Assert.Equal("+3161234", result);
    }
}
