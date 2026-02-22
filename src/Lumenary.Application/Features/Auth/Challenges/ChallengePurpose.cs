namespace Lumenary.Features.Auth.Challenges;

public enum ChallengePurpose
{
    Login,
    Register,
    PasswordReset,
    ChangeEmail,
    ChangePhone
}

public static class ChallengePurposeExtensions
{
    public static string ToValue(this ChallengePurpose purpose)
    {
        return purpose switch
        {
            ChallengePurpose.Login => "login",
            ChallengePurpose.Register => "register",
            ChallengePurpose.PasswordReset => "password_reset",
            ChallengePurpose.ChangeEmail => "change_email",
            ChallengePurpose.ChangePhone => "change_phone",
            _ => throw new ArgumentOutOfRangeException(nameof(purpose), purpose, "Unknown challenge purpose.")
        };
    }

    public static bool TryParse(string? value, out ChallengePurpose purpose)
    {
        switch (value)
        {
            case "login":
                purpose = ChallengePurpose.Login;
                return true;
            case "register":
                purpose = ChallengePurpose.Register;
                return true;
            case "password_reset":
                purpose = ChallengePurpose.PasswordReset;
                return true;
            case "change_email":
                purpose = ChallengePurpose.ChangeEmail;
                return true;
            case "change_phone":
                purpose = ChallengePurpose.ChangePhone;
                return true;
            default:
                purpose = default;
                return false;
        }
    }
}
