using System.Globalization;
using System.Net;
using System.Net.Sockets;
using Lumenary.Infrastructure.Auth.Challenges;
using Lumenary.Infrastructure.Security.Csrf;
using Lumenary.Infrastructure.Identity;
using Lumenary.Api.Security.AnonymousOnly;
using Lumenary.Application.Common.Options;
using Lumenary.Infrastructure.RateLimiting;
using Lumenary.Infrastructure.Auth.Sessions;
using Lumenary.Infrastructure.Auth.Cookies;
using Lumenary.Infrastructure.Http;
using Lumenary.Persistence;
using Lumenary.Domain.ValueObjects;
using Lumenary.Persistence.Entities;
using Lumenary.Features.Account.Services;
using Lumenary.Features.Auth.Services;
using Lumenary.Features.Auth.ResendPolicies;
using Lumenary.Common.Http;
using Lumenary.Features.Auth.Users;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using System.Threading.RateLimiting;

var builder = WebApplication.CreateBuilder(args);
ValidateAllowedHostsConfiguration(builder.Configuration, builder.Environment);

var corsAllowedOrigins = NormalizeAllowedOrigins(
    builder.Configuration.GetSection("Cors:AllowedOrigins").Get<string[]>());

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddHttpContextAccessor();
builder.Services.AddCors(options =>
{
    options.AddPolicy("Frontend", policy =>
    {
        if (corsAllowedOrigins.Length == 0)
            return;

        policy
            .WithOrigins(corsAllowedOrigins)
            .AllowAnyHeader()
            .AllowAnyMethod()
            .AllowCredentials();
    });
});
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("Default")));
builder.Services.AddScoped<IAppDbContext>(provider => provider.GetRequiredService<AppDbContext>());
builder.Services.AddOptions<AuthOptions>()
    .Bind(builder.Configuration.GetSection("Auth"))
    .Validate(
        options => !string.IsNullOrWhiteSpace(options.SessionTokenKey) &&
                   options.SessionTokenKey.Length >= 32 &&
                   !IsPlaceholderSecret(options.SessionTokenKey),
        "Auth:SessionTokenKey must be configured and at least 32 characters.")
    .Validate(
        options => string.IsNullOrWhiteSpace(options.VerificationCodeKey) ||
                   !IsPlaceholderSecret(options.VerificationCodeKey),
        "Auth:VerificationCodeKey must not use placeholder values.")
    .Validate(
        options => builder.Environment.IsDevelopment() || !options.ReturnDebugCodes,
        "Auth:ReturnDebugCodes can only be enabled in Development.")
    .ValidateOnStart();
builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    options.RequireHeaderSymmetry = true;
    options.ForwardLimit = 1;

    var knownProxies = builder.Configuration.GetSection("ForwardedHeaders:KnownProxies").Get<string[]>();
    var knownNetworks = builder.Configuration.GetSection("ForwardedHeaders:KnownNetworks").Get<string[]>();

    if ((knownProxies?.Length ?? 0) == 0 && (knownNetworks?.Length ?? 0) == 0)
        return;

    options.KnownProxies.Clear();
    options.KnownIPNetworks.Clear();

    if (knownProxies is not null)
    {
        foreach (var proxy in knownProxies)
        {
            if (!IPAddress.TryParse(proxy, out var address))
                continue;

            options.KnownProxies.Add(address);
        }
    }

    if (knownNetworks is null)
        return;

    foreach (var cidr in knownNetworks)
    {
        if (!TryParseCidr(cidr, out var network))
            continue;

        options.KnownIPNetworks.Add(network);
    }
});
builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddScoped<IAccountService, AccountService>();
builder.Services.AddScoped<IAuthChallengeService, AuthChallengeService>();
builder.Services.AddScoped<ISessionService, SessionService>();
builder.Services.AddScoped<ISessionCookieWriter, HttpSessionCookieWriter>();
builder.Services.AddScoped<IRequestMetadataAccessor, HttpRequestMetadataAccessor>();
builder.Services.AddScoped<ICurrentUserAccessor, CurrentUserAccessor>();
builder.Services.AddScoped<IUserLookupService, UserLookupService>();
builder.Services.AddScoped<IPasswordHasher<User>, PasswordHasher<User>>();
builder.Services.AddScoped<IChallengeResendPolicy, LoginResendPolicy>();
builder.Services.AddScoped<IChallengeResendPolicy, RegisterResendPolicy>();
builder.Services.AddScoped<IChallengeResendPolicy, PasswordResetResendPolicy>();
builder.Services.AddScoped<IChallengeResendPolicy, ChangeEmailResendPolicy>();
builder.Services.AddScoped<IChallengeResendPolicy, ChangePhoneResendPolicy>();
builder.Services.AddHostedService<ChallengeCleanupService>();
builder.Services.AddRateLimiter();
builder.Services.AddOptions<RateLimiterOptions>()
    .Configure<IOptions<AuthOptions>>((options, authOptions) =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

    var permitLimit = authOptions.Value.RateLimit.PermitLimit;
    var windowSeconds = authOptions.Value.RateLimit.WindowSeconds;
    var queueLimit = authOptions.Value.RateLimit.QueueLimit;

    options.AddPolicy("Auth", httpContext =>
    {
        var ip = httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        var path = httpContext.Request.Path.Value ?? string.Empty;
        var partitionKey = $"{ip}:{path}";

        return RateLimitPartition.GetFixedWindowLimiter(
            partitionKey,
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = permitLimit,
                Window = TimeSpan.FromSeconds(windowSeconds),
                QueueLimit = queueLimit,
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                AutoReplenishment = true
            });
    });
});
builder.Services.AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = SessionAuthenticationDefaults.Scheme;
        options.DefaultChallengeScheme = SessionAuthenticationDefaults.Scheme;
    })
    .AddScheme<AuthenticationSchemeOptions, SessionAuthenticationHandler>(
        SessionAuthenticationDefaults.Scheme,
        _ => { });
builder.Services.AddSingleton<IAuthorizationHandler, AnonymousOnlyHandler>();
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy(AnonymousOnlyAttribute.PolicyName,
        policy => policy.AddRequirements(new AnonymousOnlyRequirement()));
});
builder.Services.AddSingleton<AuthIdentifierRateLimiter>();

var app = builder.Build();

if (app.Environment.IsDevelopment() && app.Configuration.GetValue<bool>("SeedUser:Enabled"))
{
    using var scope = app.Services.CreateScope();
    var dbContext = scope.ServiceProvider.GetRequiredService<AppDbContext>();

    var seedSection = app.Configuration.GetSection("SeedUser");
    var name = seedSection.GetValue<string>("Name");
    var email = IdentifierNormalization.NormalizeEmail(seedSection.GetValue<string>("Email") ?? string.Empty);
    var phoneE164 =
        IdentifierNormalization.NormalizePhoneE164(seedSection.GetValue<string>("PhoneE164") ?? string.Empty);
    var password = seedSection.GetValue<string>("Password");

    if (!string.IsNullOrWhiteSpace(name) &&
        !string.IsNullOrWhiteSpace(email) &&
        !string.IsNullOrWhiteSpace(phoneE164) &&
        !string.IsNullOrWhiteSpace(password))
    {
        var seedExists = dbContext.Users.Any(user =>
            user.Email == email || user.PhoneE164 == phoneE164);

        if (!seedExists)
        {
            var user = new User
            {
                Name = name,
                Email = email,
                PhoneE164 = phoneE164,
                Role = UserRoles.Admin,
                IsActive = true,
                IsVerified = true,
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow
            };

            var passwordHasher = new PasswordHasher<User>();
            user.PasswordHash = passwordHasher.HashPassword(user, password);

            dbContext.Users.Add(user);
            dbContext.SaveChanges();
        }
    }
}

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}
else
{
    app.UseHsts();
}

app.UseForwardedHeaders();
app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();
app.UseCors("Frontend");

app.UseMiddleware<AuthIdentifierRateLimitingMiddleware>();
app.UseRateLimiter();
app.UseMiddleware<CsrfOriginValidationMiddleware>();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();

static bool IsPlaceholderSecret(string value)
    => string.Equals(value, "CHANGE_ME", StringComparison.OrdinalIgnoreCase) ||
       string.Equals(value, "CHANGEME", StringComparison.OrdinalIgnoreCase) ||
       string.Equals(value, "REPLACE_ME", StringComparison.OrdinalIgnoreCase);

static void ValidateAllowedHostsConfiguration(IConfiguration configuration, IWebHostEnvironment environment)
{
    if (environment.IsDevelopment())
        return;

    var allowedHosts = configuration["AllowedHosts"];
    if (string.IsNullOrWhiteSpace(allowedHosts))
        throw new InvalidOperationException("AllowedHosts must be configured in non-Development environments.");

    var hosts = allowedHosts.Split([';', ','], StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
    if (hosts.Length == 0 || hosts.Any(static host => host == "*"))
    {
        throw new InvalidOperationException(
            "AllowedHosts cannot be wildcard (*) in non-Development environments.");
    }
}

static string[] NormalizeAllowedOrigins(string[]? origins)
{
    if (origins is null || origins.Length == 0)
        return [];

    return origins
        .Where(static origin => !string.IsNullOrWhiteSpace(origin))
        .Select(static origin => origin.Trim().TrimEnd('/'))
        .Where(static origin =>
            Uri.TryCreate(origin, UriKind.Absolute, out var uri) &&
            (string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase) ||
             string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)))
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .ToArray();
}

static bool TryParseCidr(string? value, out System.Net.IPNetwork network)
{
    network = default!;
    if (string.IsNullOrWhiteSpace(value))
        return false;

    var parts = value.Split('/', 2, StringSplitOptions.TrimEntries);
    if (parts.Length != 2)
        return false;

    if (!IPAddress.TryParse(parts[0], out var address))
        return false;

    if (!int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out var prefixLength))
        return false;

    var maxPrefixLength = address.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
    if (prefixLength < 0 || prefixLength > maxPrefixLength)
        return false;

    network = new System.Net.IPNetwork(address, prefixLength);
    return true;
}

public partial class Program
{
}
