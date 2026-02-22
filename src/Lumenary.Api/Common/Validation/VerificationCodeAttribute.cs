using System.ComponentModel.DataAnnotations;
using Lumenary.Common.Validation;

namespace Lumenary.Api.Common.Validation;

[AttributeUsage(AttributeTargets.Property | AttributeTargets.Field | AttributeTargets.Parameter)]
public sealed class VerificationCodeAttribute()
    : ValidationAttribute("The {0} field must be a valid verification code.")
{
    public override bool IsValid(object? value)
    {
        if (value is not string text)
            return false;

        if (text.Length != ValidationConstants.VerificationCodeLength)
            return false;

        foreach (var ch in text)
        {
            if (!char.IsDigit(ch))
                return false;
        }

        return true;
    }
}
