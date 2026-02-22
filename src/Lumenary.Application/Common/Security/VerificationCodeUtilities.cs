using System.Security.Cryptography;
using System.Text;

namespace Lumenary.Infrastructure.Security.Verification;

public static class VerificationCodeUtilities
{
    public static string CreateCode(int length = 6)
    {
        if (length <= 0)
            throw new ArgumentOutOfRangeException(nameof(length));

        var digits = new char[length];
        for (var i = 0; i < length; i++)
        {
            digits[i] = (char)('0' + RandomNumberGenerator.GetInt32(0, 10));
        }

        return new string(digits);
    }

    public static byte[] ComputeHash(string code, string? secret)
    {
        var codeBytes = Encoding.UTF8.GetBytes(code);

        if (string.IsNullOrWhiteSpace(secret))
            return SHA256.HashData(codeBytes);

        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
        return hmac.ComputeHash(codeBytes);
    }
}
