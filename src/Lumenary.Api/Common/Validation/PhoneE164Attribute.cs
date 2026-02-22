using System.ComponentModel.DataAnnotations;
using System.Text.RegularExpressions;
using Lumenary.Infrastructure.Identity;

namespace Lumenary.Api.Common.Validation;

[AttributeUsage(AttributeTargets.Property | AttributeTargets.Field | AttributeTargets.Parameter)]
public sealed class PhoneE164Attribute() : ValidationAttribute("The {0} field must be a valid E.164 phone number.")
{
    private static readonly Regex PhoneRegex = new(@"^\+[1-9]\d{1,14}$", RegexOptions.Compiled);

    public override bool IsValid(object? value)
    {
        if (value is not string text)
            return false;

        if (string.IsNullOrWhiteSpace(text))
            return false;

        var normalized = IdentifierNormalization.NormalizePhoneE164(text);
        return PhoneRegex.IsMatch(normalized);
    }
}
