using Lumenary.Api.Common.Validation;

namespace Lumenary.Api.Tests.Common.Validation;

public sealed class NotEmptyGuidAttributeTests
{
    private static readonly NotEmptyGuidAttribute Sut = new();

    [Fact]
    public void IsValid_WhenValueIsNull_ThenReturnsFalse()
    {
        Assert.False(Sut.IsValid(null));
    }

    [Fact]
    public void IsValid_WhenValueIsGuidEmpty_ThenReturnsFalse()
    {
        Assert.False(Sut.IsValid(Guid.Empty));
    }

    [Fact]
    public void IsValid_WhenValueIsNonEmptyGuid_ThenReturnsTrue()
    {
        Assert.True(Sut.IsValid(Guid.NewGuid()));
    }

    [Fact]
    public void IsValid_WhenValueIsNotGuid_ThenReturnsFalse()
    {
        Assert.False(Sut.IsValid("not-a-guid"));
    }
}
