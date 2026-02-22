using System.ComponentModel.DataAnnotations;

namespace Lumenary.Api.Common.Validation;

[AttributeUsage(AttributeTargets.Property | AttributeTargets.Field | AttributeTargets.Parameter)]
public sealed class NotWhiteSpaceAttribute() : ValidationAttribute("The {0} field is required.")
{
    public override bool IsValid(object? value)
    {
        if (value is null)
            return false;

        return value is not string text || !string.IsNullOrWhiteSpace(text);
    }
}
