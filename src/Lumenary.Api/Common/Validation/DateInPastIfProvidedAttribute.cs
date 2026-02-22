using System.ComponentModel.DataAnnotations;

namespace Lumenary.Api.Common.Validation;

[AttributeUsage(AttributeTargets.Property | AttributeTargets.Field | AttributeTargets.Parameter)]
public sealed class DateInPastIfProvidedAttribute : ValidationAttribute
{
    public DateInPastIfProvidedAttribute()
        : base("The {0} field must be a past date.")
    {
    }

    public override bool IsValid(object? value)
    {
        if (value is null)
        {
            return true;
        }

        if (value is not DateTime date)
        {
            return false;
        }

        if (date == default)
        {
            return false;
        }

        return date.Date <= DateTime.UtcNow.Date;
    }
}
