using System.ComponentModel.DataAnnotations;

namespace backend.Validation;

[AttributeUsage(AttributeTargets.Property | AttributeTargets.Field | AttributeTargets.Parameter)]
public sealed class PasswordStrengthAttribute()
    : ValidationAttribute("The {0} field must be at least {1} characters and contain letters and digits.")
{
    public override bool IsValid(object? value)
    {
        if (value is not string text)
            return false;

        if (text.Length < ValidationConstants.PasswordMinLength)
            return false;

        var hasLetter = false;
        var hasDigit = false;

        foreach (var ch in text)
        {
            if (char.IsLetter(ch))
                hasLetter = true;
            else if (char.IsDigit(ch))
                hasDigit = true;

            if (hasLetter && hasDigit)
                return true;
        }

        return false;
    }

    public override string FormatErrorMessage(string name)
        => $"The {name} field must be at least {ValidationConstants.PasswordMinLength} characters and contain letters and digits.";
}
