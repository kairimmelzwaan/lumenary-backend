using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.WebUtilities;

namespace Lumenary.Infrastructure.Auth.Sessions;

public static class SessionTokenUtilities
{
    public static string CreateToken(string? secret, out byte[] tokenHash)
    {
        var tokenBytes = RandomNumberGenerator.GetBytes(32);
        tokenHash = ComputeHash(tokenBytes, secret);
        return WebEncoders.Base64UrlEncode(tokenBytes);
    }

    public static bool TryComputeHash(string token, string? secret, out byte[] tokenHash)
    {
        if (string.IsNullOrWhiteSpace(token))
        {
            tokenHash = Array.Empty<byte>();
            return false;
        }

        try
        {
            var tokenBytes = WebEncoders.Base64UrlDecode(token);
            tokenHash = ComputeHash(tokenBytes, secret);
            return true;
        }
        catch (FormatException)
        {
            tokenHash = Array.Empty<byte>();
            return false;
        }
    }

    private static byte[] ComputeHash(byte[] tokenBytes, string? secret)
    {
        if (string.IsNullOrWhiteSpace(secret))
        {
            return SHA256.HashData(tokenBytes);
        }

        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
        return hmac.ComputeHash(tokenBytes);
    }
}
