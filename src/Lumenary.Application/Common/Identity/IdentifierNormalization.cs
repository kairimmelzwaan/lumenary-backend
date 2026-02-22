using System.Text;

namespace Lumenary.Infrastructure.Identity;

public static class IdentifierNormalization
{
    public static string NormalizeEmail(string email)
    {
        return email.Trim().ToLowerInvariant();
    }

    public static string NormalizePhoneE164(string phone)
    {
        var trimmed = phone.Trim();
        if (trimmed.StartsWith("00", StringComparison.Ordinal))
            trimmed = "+" + trimmed.Substring(2);

        var builder = new StringBuilder(trimmed.Length);
        foreach (var ch in trimmed)
        {
            if (char.IsDigit(ch))
            {
                builder.Append(ch);
                continue;
            }

            if (ch == '+' && builder.Length == 0)
                builder.Append(ch);
        }

        return builder.ToString();
    }
}
