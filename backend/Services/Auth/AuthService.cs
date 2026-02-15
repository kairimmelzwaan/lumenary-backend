using backend.Auth.Challenges;
using backend.Auth.Identity;
using backend.Auth.Options;
using backend.Auth.Verification;
using backend.Data;
using backend.Dtos;
using backend.Models;
using backend.Services.Results;
using backend.Services.Users;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace backend.Services.Auth;

public sealed class AuthService(
    AppDbContext dbContext,
    IAuthChallengeService authChallengeService,
    ISessionService sessionService,
    ICurrentUserAccessor currentUserAccessor,
    IPasswordHasher<User> passwordHasher,
    IOptions<AuthOptions> authOptions)
    : IAuthService
{
    private static readonly User DummyPasswordUser = new()
    {
        Name = "dummy",
        Email = "dummy@example.com",
        PhoneE164 = "+10000000000",
        PasswordHash = string.Empty,
        Role = UserRoles.Client,
        IsActive = true,
        IsVerified = true,
        CreatedAt = DateTime.UnixEpoch,
        UpdatedAt = DateTime.UnixEpoch
    };
    private static readonly string DummyPasswordHash =
        new PasswordHasher<User>().HashPassword(DummyPasswordUser, "dummy-password-not-used");

    private readonly AuthOptions _authOptions = authOptions.Value;

    public async Task<Result<LoginResponse>> LoginAsync(LoginRequest request, CancellationToken cancellationToken)
    {
        var normalizedEmail = IdentifierNormalization.NormalizeEmail(request.Email);
        var user = await dbContext.Users
            .AsNoTracking()
            .FirstOrDefaultAsync(u => u.Email == normalizedEmail, cancellationToken);

        if (user == null || !user.IsActive || !user.IsVerified)
        {
            _ = passwordHasher.VerifyHashedPassword(DummyPasswordUser, DummyPasswordHash, request.Password);
            return CreateGenericLoginResponse();
        }

        var passwordResult = passwordHasher.VerifyHashedPassword(user, user.PasswordHash, request.Password);
        if (passwordResult == PasswordVerificationResult.Failed)
            return CreateGenericLoginResponse();

        var now = DateTime.UtcNow;
        var challenge = await authChallengeService.CreateChallengeAsync(
            new AuthChallengeRequest(user.Id, ChallengePurpose.Login, null, user.PhoneE164),
            now,
            cancellationToken);

        return Result<LoginResponse>.Ok(new LoginResponse(challenge.ChallengeId, DebugCodeOrNull(challenge.Code)));
    }

    public async Task<Result> LoginVerifyAsync(LoginVerifyRequest request, CancellationToken cancellationToken)
    {
        var now = DateTime.UtcNow;
        var challengeResult = await authChallengeService.GetActiveChallengeAsync(
            request.ChallengeId,
            ChallengePurpose.Login,
            null,
            now,
            cancellationToken);

        if (!challengeResult.IsSuccess)
            return Result.Unauthorized();

        var challenge = challengeResult.Value!;
        var verifyResult = await authChallengeService.VerifyChallengeCodeAsync(
            challenge,
            request.Code,
            now,
            cancellationToken);

        if (!verifyResult.IsSuccess)
            return verifyResult;

        await sessionService.CreateSessionAndSetCookieAsync(challenge.User, now, cancellationToken);
        return Result.Ok();
    }

    public async Task<Result<RegisterResponse>> RegisterAsync(RegisterRequest request,
        CancellationToken cancellationToken)
    {
        var normalizedEmail = IdentifierNormalization.NormalizeEmail(request.Email);
        var normalizedPhone = IdentifierNormalization.NormalizePhoneE164(request.PhoneE164);

        var alreadyExists = await dbContext.Users
            .AnyAsync(
                u => u.Email == normalizedEmail || u.PhoneE164 == normalizedPhone,
                cancellationToken);

        if (alreadyExists)
        {
            return Result<RegisterResponse>.Ok(new RegisterResponse(Guid.NewGuid(), CreateDebugCodeIfEnabled()));
        }

        var therapist = await dbContext.Users
            .AsNoTracking()
            .FirstOrDefaultAsync(u => u.Role == UserRoles.Therapist && u.IsActive, cancellationToken);

        if (therapist == null)
            return Result<RegisterResponse>.ServiceUnavailable();

        var now = DateTime.UtcNow;
        var userId = Guid.NewGuid();
        var user = new User
        {
            Id = userId,
            Name = request.Name,
            Email = normalizedEmail,
            PhoneE164 = normalizedPhone,
            Role = UserRoles.Client,
            IsActive = true,
            IsVerified = false,
            MustChangePassword = false,
            CreatedAt = now,
            UpdatedAt = now
        };

        user.PasswordHash = passwordHasher.HashPassword(user, request.Password);

        var client = new Client
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            TherapistUserId = therapist.Id,
            DateOfBirth = request.DateOfBirth.Date,
            CreatedAt = now,
            UpdatedAt = now
        };

        dbContext.Users.Add(user);
        dbContext.Clients.Add(client);

        var challenge = await authChallengeService.CreateChallengeAsync(
            new AuthChallengeRequest(userId, ChallengePurpose.Register, null, normalizedPhone, Guid.NewGuid()),
            now,
            cancellationToken);

        return Result<RegisterResponse>.Ok(new RegisterResponse(challenge.ChallengeId, DebugCodeOrNull(challenge.Code)));
    }

    public async Task<Result> RegisterVerifyAsync(RegisterVerifyRequest request, CancellationToken cancellationToken)
    {
        var now = DateTime.UtcNow;
        var challengeResult = await authChallengeService.GetActiveChallengeAsync(
            request.ChallengeId,
            ChallengePurpose.Register,
            null,
            now,
            cancellationToken);

        if (!challengeResult.IsSuccess)
        {
            return Result.Unauthorized();
        }

        var challenge = challengeResult.Value!;
        var verifyResult = await authChallengeService.VerifyChallengeCodeAsync(
            challenge,
            request.Code,
            now,
            cancellationToken);

        if (!verifyResult.IsSuccess)
            return verifyResult;

        challenge.User.IsVerified = true;
        challenge.User.UpdatedAt = now;

        await sessionService.CreateSessionAndSetCookieAsync(challenge.User, now, cancellationToken);
        return Result.Ok();
    }

    public async Task<Result<PasswordResetResponse>> PasswordResetAsync(
        PasswordResetRequest request,
        CancellationToken cancellationToken)
    {
        var normalizedEmail = IdentifierNormalization.NormalizeEmail(request.Email);
        var user = await dbContext.Users
            .AsNoTracking()
            .FirstOrDefaultAsync(u => u.Email == normalizedEmail && u.IsActive, cancellationToken);

        if (user == null)
            return Result<PasswordResetResponse>.Ok(new PasswordResetResponse(Guid.NewGuid()));

        var now = DateTime.UtcNow;
        var challenge = await authChallengeService.CreateChallengeAsync(
            new AuthChallengeRequest(user.Id, ChallengePurpose.PasswordReset, null, user.PhoneE164, Guid.NewGuid()),
            now,
            cancellationToken);

        return Result<PasswordResetResponse>.Ok(new PasswordResetResponse(challenge.ChallengeId));
    }

    public async Task<Result> PasswordResetVerifyAsync(
        PasswordResetVerifyRequest request,
        CancellationToken cancellationToken)
    {
        var now = DateTime.UtcNow;
        var challengeResult = await authChallengeService.GetActiveChallengeAsync(
            request.ChallengeId,
            ChallengePurpose.PasswordReset,
            null,
            now,
            cancellationToken);

        if (!challengeResult.IsSuccess)
            return Result.Unauthorized();

        var challenge = challengeResult.Value!;
        if (string.IsNullOrWhiteSpace(challenge.TargetPhoneE164) ||
            !string.Equals(challenge.TargetPhoneE164, challenge.User.PhoneE164, StringComparison.Ordinal))
        {
            return Result.BadRequest();
        }

        var verifyResult = await authChallengeService.VerifyChallengeCodeAsync(
            challenge,
            request.Code,
            now,
            cancellationToken);

        if (!verifyResult.IsSuccess)
            return verifyResult;

        challenge.User.PasswordHash = passwordHasher.HashPassword(challenge.User, request.NewPassword);
        challenge.User.MustChangePassword = false;
        challenge.User.UpdatedAt = now;

        var sessions = await dbContext.Sessions
            .Where(s => s.UserId == challenge.UserId && s.RevokedAt == null)
            .ToListAsync(cancellationToken);

        foreach (var session in sessions)
        {
            session.RevokedAt = now;
        }

        await dbContext.SaveChangesAsync(cancellationToken);
        return Result.Ok();
    }

    public async Task<Result<ResendCodeResponse>> ResendChallengeCodeAsync(
        ResendCodeRequest request,
        CancellationToken cancellationToken)
    {
        var now = DateTime.UtcNow;
        var requesterUserId = currentUserAccessor.TryGetUserId(out var userId) ? userId : (Guid?)null;

        var resendResult = await authChallengeService.ResendChallengeAsync(
            request.ChallengeId,
            requesterUserId,
            now,
            cancellationToken);

        if (!resendResult.IsSuccess)
        {
            return Result<ResendCodeResponse>.Ok(
                new ResendCodeResponse(request.ChallengeId, CreateDebugCodeIfEnabled()));
        }

        var payload = resendResult.Value!;
        return Result<ResendCodeResponse>.Ok(
            new ResendCodeResponse(payload.ChallengeId, DebugCodeOrNull(payload.Code)));
    }

    private Result<LoginResponse> CreateGenericLoginResponse()
        => Result<LoginResponse>.Ok(new LoginResponse(Guid.NewGuid(), CreateDebugCodeIfEnabled()));

    private string? CreateDebugCodeIfEnabled()
        => _authOptions.ReturnDebugCodes ? VerificationCodeUtilities.CreateCode() : null;

    private string? DebugCodeOrNull(string? code)
    {
        if (!_authOptions.ReturnDebugCodes || string.IsNullOrWhiteSpace(code))
            return null;

        return code;
    }
}
