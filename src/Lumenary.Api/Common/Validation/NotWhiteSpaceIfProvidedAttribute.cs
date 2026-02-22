using System.ComponentModel.DataAnnotations;

namespace Lumenary.Api.Common.Validation;

[AttributeUsage(AttributeTargets.Property | AttributeTargets.Field | AttributeTargets.Parameter)]
public sealed class NotWhiteSpaceIfProvidedAttribute : ValidationAttribute
{
    public NotWhiteSpaceIfProvidedAttribute()
        : base("The {0} field must not be empty.")
    {
    }

    public override bool IsValid(object? value)
    {
        if (value is null)
        {
            return true;
        }

        if (value is not string text)
        {
            return false;
        }

        return !string.IsNullOrWhiteSpace(text);
    }
}
