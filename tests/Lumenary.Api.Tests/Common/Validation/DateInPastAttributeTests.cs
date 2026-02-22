using Lumenary.Api.Common.Validation;

namespace Lumenary.Api.Tests.Common.Validation;

public sealed class DateInPastAttributeTests
{
    private static readonly DateInPastAttribute Sut = new();

    [Fact]
    public void IsValid_WhenValueIsNull_ThenReturnsFalse()
    {
        Assert.False(Sut.IsValid(null));
    }

    [Fact]
    public void IsValid_WhenValueIsNotDateTime_ThenReturnsFalse()
    {
        Assert.False(Sut.IsValid("2020-01-01"));
    }

    [Fact]
    public void IsValid_WhenValueIsDefaultDateTime_ThenReturnsFalse()
    {
        Assert.False(Sut.IsValid(default(DateTime)));
    }

    [Fact]
    public void IsValid_WhenValueIsPastDate_ThenReturnsTrue()
    {
        var pastDate = DateTime.UtcNow.Date.AddDays(-1);

        Assert.True(Sut.IsValid(pastDate));
    }

    [Fact]
    public void IsValid_WhenValueIsToday_ThenReturnsTrue()
    {
        var today = DateTime.UtcNow.Date;

        Assert.True(Sut.IsValid(today));
    }

    [Fact]
    public void IsValid_WhenValueIsFutureDate_ThenReturnsFalse()
    {
        var futureDate = DateTime.UtcNow.Date.AddDays(1);

        Assert.False(Sut.IsValid(futureDate));
    }
}
