using backend.Auth.Challenges;
using backend.Auth.Identity;
using backend.Auth.AnonymousOnly;
using backend.Auth.Options;
using backend.Auth.RateLimiting;
using backend.Auth.Sessions;
using backend.Data;
using backend.Models;
using backend.Services.Account;
using backend.Services.Appointments;
using backend.Services.Appointments.Authorization;
using backend.Services.Auth;
using backend.Services.Auth.ResendPolicies;
using backend.Services.Requests;
using backend.Services.Users;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using System.Threading.RateLimiting;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddHttpContextAccessor();
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("Default")));
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
    .ValidateOnStart();
builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    options.KnownIPNetworks.Clear();
    options.KnownProxies.Clear();
});
builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddScoped<IAccountService, AccountService>();
builder.Services.AddScoped<IAppointmentsService, AppointmentsService>();
builder.Services.AddScoped<IAppointmentsAuthorizationService, AppointmentsAuthorizationService>();
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

if (app.Configuration.GetValue<bool>("SeedUser:Enabled"))
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

app.UseForwardedHeaders();
app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseMiddleware<AuthIdentifierRateLimitingMiddleware>();
app.UseRateLimiter();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();

static bool IsPlaceholderSecret(string value)
    => string.Equals(value, "CHANGE_ME", StringComparison.OrdinalIgnoreCase) ||
       string.Equals(value, "CHANGEME", StringComparison.OrdinalIgnoreCase) ||
       string.Equals(value, "REPLACE_ME", StringComparison.OrdinalIgnoreCase);
