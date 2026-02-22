namespace Lumenary.Domain.ValueObjects;

public static class UserRoles
{
    public const string Owner = "owner";
    public const string Admin = "admin";
    public const string OrgManager = "org_manager";
    public const string ClinicalManager = "clinical_manager";
    public const string Therapist = "therapist";
    public const string IntakeCoordinator = "intake_coordinator";
    public const string Billing = "billing";
    public const string Support = "support";
    public const string Compliance = "compliance";
    public const string Client = "client";

    public static readonly string[] All =
    {
        Owner,
        Admin,
        OrgManager,
        ClinicalManager,
        Therapist,
        IntakeCoordinator,
        Billing,
        Support,
        Compliance,
        Client
    };
}
