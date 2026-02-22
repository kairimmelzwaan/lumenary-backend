using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;

namespace Lumenary.Api.Tests.Integration;

public class ApiWebApplicationFactory : WebApplicationFactory<Program>
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Development");

        builder.ConfigureAppConfiguration((_, configurationBuilder) =>
        {
            var settings = new Dictionary<string, string?>
            {
                ["AllowedHosts"] = "*",
                ["SeedUser:Enabled"] = "false",
                ["Auth:SessionTokenKey"] = "01234567890123456789012345678901",
                ["Auth:VerificationCodeKey"] = "abcdefghijklmnopqrstuvwxyz123456",
                ["Auth:ReturnDebugCodes"] = "false",
                ["Auth:CookieName"] = "lumenary_session",
                ["Auth:RateLimit:PermitLimit"] = "1000",
                ["Auth:RateLimit:WindowSeconds"] = "60",
                ["Auth:RateLimit:QueueLimit"] = "0",
                ["Auth:IdentifierRateLimit:PermitLimit"] = "1000",
                ["Auth:IdentifierRateLimit:WindowSeconds"] = "60",
                ["Auth:IdentifierRateLimit:QueueLimit"] = "0",
                ["ConnectionStrings:Default"] = "Host=localhost;Database=not-used;"
            };

            configurationBuilder.AddInMemoryCollection(settings);
        });
    }
}
