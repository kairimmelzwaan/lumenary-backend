using Lumenary.Features.Auth.Challenges;
using Lumenary.Infrastructure.Identity;
using Lumenary.Persistence;
using Lumenary.Features.Account.Models;
using Lumenary.Features.Auth.Models;
using Lumenary.Persistence.Entities;
using Lumenary.Features.Auth.Services;
using Lumenary.Common.Results;
using Lumenary.Features.Auth.Users;
using Lumenary.Application.Common.Options;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Lumenary.Features.Account.Services;

public sealed class AccountService(
    IAppDbContext dbContext,
    IAuthChallengeService authChallengeService,
    ISessionService sessionService,
    ICurrentUserAccessor currentUserAccessor,
    IUserLookupService userLookupService,
    IPasswordHasher<User> passwordHasher,
    IOptions<AuthOptions> authOptions)
    : IAccountService
{
    private readonly AuthOptions _authOptions = authOptions.Value;

    public async Task<Result<AccountMeResponse>> GetMeAsync(CancellationToken cancellationToken)
    {
        if (!currentUserAccessor.TryGetUserId(out var userId))
            return Result<AccountMeResponse>.Unauthorized();

        var user = await userLookupService.GetActiveUserWithClientProfileAsync(
            userId,
            UserTrackingMode.ReadOnly,
            cancellationToken);

        if (user == null)
            return Result<AccountMeResponse>.Unauthorized();

        return Result<AccountMeResponse>.Ok(new AccountMeResponse(
            user.Name,
            user.Email,
            user.PhoneE164,
            user.ClientProfile?.DateOfBirth));
    }

    public async Task<Result> UpdateProfileAsync(UpdateProfileRequest request, CancellationToken cancellationToken)
    {
        if (request.Name is null && request.DateOfBirth is null)
            return Result.BadRequest();

        if (!currentUserAccessor.TryGetUserId(out var userId))
            return Result.Unauthorized();

        var user = await userLookupService.GetActiveUserWithClientProfileAsync(
            userId,
            UserTrackingMode.Tracked,
            cancellationToken);

        if (user == null)
            return Result.Unauthorized();

        var now = DateTime.UtcNow;
        var updated = false;

        if (request.Name is not null)
        {
            user.Name = request.Name;
            updated = true;
        }

        if (request.DateOfBirth.HasValue)
        {
            if (user.ClientProfile == null)
                return Result.BadRequest();

            user.ClientProfile.DateOfBirth = request.DateOfBirth.Value.Date;
            user.ClientProfile.UpdatedAt = now;
            updated = true;
        }

        if (!updated)
            return Result.BadRequest();

        user.UpdatedAt = now;
        await dbContext.SaveChangesAsync(cancellationToken);

        return Result.Ok();
    }

    public async Task<Result> ChangePasswordAsync(PasswordChangeRequest request, CancellationToken cancellationToken)
    {
        if (string.Equals(request.CurrentPassword, request.NewPassword, StringComparison.Ordinal))
            return Result.BadRequest();

        if (!currentUserAccessor.TryGetUserId(out var userId))
            return Result.Unauthorized();

        var user = await userLookupService.GetActiveUserAsync(userId, UserTrackingMode.Tracked, cancellationToken);
        if (user == null)
            return Result.Unauthorized();

        var passwordResult = passwordHasher.VerifyHashedPassword(user, user.PasswordHash, request.CurrentPassword);
        if (passwordResult == PasswordVerificationResult.Failed)
            return Result.Unauthorized();

        var now = DateTime.UtcNow;
        user.PasswordHash = passwordHasher.HashPassword(user, request.NewPassword);
        user.MustChangePassword = false;
        user.UpdatedAt = now;

        var sessionsQuery = dbContext.Sessions
            .Where(s => s.UserId == userId && s.RevokedAt == null);

        if (currentUserAccessor.TryGetSessionId(out var currentSessionId))
        {
            sessionsQuery = sessionsQuery.Where(s => s.Id != currentSessionId);
        }

        await RevokeSessionsAsync(sessionsQuery, now, cancellationToken);

        await dbContext.SaveChangesAsync(cancellationToken);
        return Result.Ok();
    }

    public async Task<Result<ChangeEmailResponse>> ChangeEmailAsync(
        ChangeEmailRequest request,
        CancellationToken cancellationToken)
    {
        if (!currentUserAccessor.TryGetUserId(out var userId))
            return Result<ChangeEmailResponse>.Unauthorized();

        var user = await userLookupService.GetActiveUserAsync(userId, UserTrackingMode.Tracked, cancellationToken);
        if (user == null)
            return Result<ChangeEmailResponse>.Unauthorized();

        var normalizedEmail = IdentifierNormalization.NormalizeEmail(request.Email);
        if (string.Equals(user.Email, normalizedEmail, StringComparison.Ordinal))
            return Result<ChangeEmailResponse>.Conflict();

        var emailInUse = await dbContext.Users.AnyAsync(
            u => u.Id != userId &&
                 (u.Email == normalizedEmail || u.PendingEmail == normalizedEmail),
            cancellationToken);

        if (emailInUse)
            return Result<ChangeEmailResponse>.Conflict();

        var now = DateTime.UtcNow;
        user.PendingEmail = normalizedEmail;
        user.PendingEmailRequestedAt = now;
        user.UpdatedAt = now;

        try
        {
            var challenge = await authChallengeService.CreateChallengeAsync(
                new AuthChallengeRequest(userId, ChallengePurpose.ChangeEmail, normalizedEmail, null, Guid.NewGuid()),
                now,
                cancellationToken);
            await dbContext.SaveChangesAsync(cancellationToken);
            return Result<ChangeEmailResponse>.Ok(
                new ChangeEmailResponse(challenge.ChallengeId, DebugCodeOrNull(challenge.Code)));
        }
        catch (DbUpdateException ex) when (dbContext.IsUniqueConstraintViolation(ex))
        {
            dbContext.ClearChangeTracker();
            return Result<ChangeEmailResponse>.Conflict();
        }
    }

    public async Task<Result> ChangeEmailVerifyAsync(
        ChangeEmailVerifyRequest request,
        CancellationToken cancellationToken)
    {
        if (!currentUserAccessor.TryGetUserId(out var userId))
            return Result.Unauthorized();

        var now = DateTime.UtcNow;
        var challengeResult = await GetOwnActiveChallengeOrUnauthorizedAsync(
            userId,
            request.ChallengeId,
            ChallengePurpose.ChangeEmail,
            now,
            cancellationToken);

        if (!challengeResult.IsSuccess)
            return Result.Unauthorized();

        var challenge = challengeResult.Value!;
        if (!HasMatchingPendingEmail(challenge))
            return Result.BadRequest();

        var verifyResult = await authChallengeService.VerifyChallengeCodeAsync(
            challenge,
            request.Code,
            now,
            cancellationToken);

        if (!verifyResult.IsSuccess)
            return verifyResult;

        challenge.User.Email = challenge.User.PendingEmail!;
        challenge.User.PendingEmail = null;
        challenge.User.PendingEmailRequestedAt = null;
        challenge.User.UpdatedAt = now;

        await dbContext.SaveChangesAsync(cancellationToken);
        return Result.Ok();
    }

    public async Task<Result> ChangeEmailCancelAsync(
        ChangeEmailCancelRequest request,
        CancellationToken cancellationToken)
    {
        if (!currentUserAccessor.TryGetUserId(out var userId))
            return Result.Unauthorized();

        var now = DateTime.UtcNow;
        var challengeResult = await GetOwnActiveChallengeOrNotFoundAsync(
            userId,
            request.ChallengeId,
            ChallengePurpose.ChangeEmail,
            now,
            cancellationToken);

        if (!challengeResult.IsSuccess)
            return Result.NotFound();

        var challenge = challengeResult.Value!;
        if (!HasMatchingPendingEmail(challenge))
            return Result.BadRequest();

        challenge.ExpiresAt = now;
        challenge.User.PendingEmail = null;
        challenge.User.PendingEmailRequestedAt = null;
        challenge.User.UpdatedAt = now;

        await dbContext.SaveChangesAsync(cancellationToken);
        return Result.Ok();
    }

    public async Task<Result<ChangePhoneResponse>> ChangePhoneAsync(
        ChangePhoneRequest request,
        CancellationToken cancellationToken)
    {
        if (!currentUserAccessor.TryGetUserId(out var userId))
            return Result<ChangePhoneResponse>.Unauthorized();

        var user = await userLookupService.GetActiveUserAsync(userId, UserTrackingMode.Tracked, cancellationToken);
        if (user == null)
            return Result<ChangePhoneResponse>.Unauthorized();

        var normalizedPhone = IdentifierNormalization.NormalizePhoneE164(request.PhoneE164);
        if (string.Equals(user.PhoneE164, normalizedPhone, StringComparison.Ordinal))
            return Result<ChangePhoneResponse>.Conflict();

        var phoneInUse = await dbContext.Users.AnyAsync(
            u => u.Id != userId &&
                 (u.PhoneE164 == normalizedPhone || u.PendingPhoneE164 == normalizedPhone),
            cancellationToken);

        if (phoneInUse)
            return Result<ChangePhoneResponse>.Conflict();

        var now = DateTime.UtcNow;
        user.PendingPhoneE164 = normalizedPhone;
        user.PendingPhoneRequestedAt = now;
        user.UpdatedAt = now;

        try
        {
            var challenge = await authChallengeService.CreateChallengeAsync(
                new AuthChallengeRequest(userId, ChallengePurpose.ChangePhone, null, normalizedPhone, Guid.NewGuid()),
                now,
                cancellationToken);
            await dbContext.SaveChangesAsync(cancellationToken);
            return Result<ChangePhoneResponse>.Ok(
                new ChangePhoneResponse(challenge.ChallengeId, DebugCodeOrNull(challenge.Code)));
        }
        catch (DbUpdateException ex) when (dbContext.IsUniqueConstraintViolation(ex))
        {
            dbContext.ClearChangeTracker();
            return Result<ChangePhoneResponse>.Conflict();
        }
    }

    public async Task<Result> ChangePhoneVerifyAsync(
        ChangePhoneVerifyRequest request,
        CancellationToken cancellationToken)
    {
        if (!currentUserAccessor.TryGetUserId(out var userId))
            return Result.Unauthorized();

        var now = DateTime.UtcNow;
        var challengeResult = await GetOwnActiveChallengeOrUnauthorizedAsync(
            userId,
            request.ChallengeId,
            ChallengePurpose.ChangePhone,
            now,
            cancellationToken);

        if (!challengeResult.IsSuccess)
            return Result.Unauthorized();

        var challenge = challengeResult.Value!;
        if (!HasMatchingPendingPhone(challenge))
            return Result.BadRequest();

        var verifyResult = await authChallengeService.VerifyChallengeCodeAsync(
            challenge,
            request.Code,
            now,
            cancellationToken);

        if (!verifyResult.IsSuccess)
            return verifyResult;

        challenge.User.PhoneE164 = challenge.User.PendingPhoneE164!;
        challenge.User.PendingPhoneE164 = null;
        challenge.User.PendingPhoneRequestedAt = null;
        challenge.User.UpdatedAt = now;

        await dbContext.SaveChangesAsync(cancellationToken);
        return Result.Ok();
    }

    public async Task<Result> ChangePhoneCancelAsync(
        ChangePhoneCancelRequest request,
        CancellationToken cancellationToken)
    {
        if (!currentUserAccessor.TryGetUserId(out var userId))
            return Result.Unauthorized();

        var now = DateTime.UtcNow;
        var challengeResult = await GetOwnActiveChallengeOrNotFoundAsync(
            userId,
            request.ChallengeId,
            ChallengePurpose.ChangePhone,
            now,
            cancellationToken);

        if (!challengeResult.IsSuccess)
            return Result.NotFound();

        var challenge = challengeResult.Value!;
        if (!HasMatchingPendingPhone(challenge))
            return Result.BadRequest();

        challenge.ExpiresAt = now;
        challenge.User.PendingPhoneE164 = null;
        challenge.User.PendingPhoneRequestedAt = null;
        challenge.User.UpdatedAt = now;

        await dbContext.SaveChangesAsync(cancellationToken);
        return Result.Ok();
    }

    public async Task<Result<SessionsOverviewResponse>> GetSessionsAsync(CancellationToken cancellationToken)
    {
        if (!currentUserAccessor.TryGetUserId(out var userId))
            return Result<SessionsOverviewResponse>.Unauthorized();

        var now = DateTime.UtcNow;
        var sessions = await dbContext.Sessions
            .AsNoTracking()
            .Where(s => s.UserId == userId && s.RevokedAt == null && s.ExpiresAt > now)
            .OrderByDescending(s => s.CreatedAt)
            .Select(s => new SessionResponse(
                s.CreatedAt,
                s.LastSeenAt,
                s.ExpiresAt,
                s.UserAgent,
                s.IpAddress))
            .ToListAsync(cancellationToken);

        var lastSession = sessions.FirstOrDefault();
        return Result<SessionsOverviewResponse>.Ok(new SessionsOverviewResponse(
            lastSession?.CreatedAt,
            lastSession?.UserAgent,
            lastSession?.IpAddress,
            sessions));
    }

    public async Task<Result> LogoutAsync(CancellationToken cancellationToken)
    {
        if (!currentUserAccessor.TryGetSessionId(out var sessionId))
            return Result.Unauthorized();

        var now = DateTime.UtcNow;
        var revoked = await RevokeSessionsAsync(
            dbContext.Sessions.Where(s => s.Id == sessionId && s.RevokedAt == null),
            now,
            cancellationToken);

        if (UsesInMemoryProvider() && revoked > 0)
            await dbContext.SaveChangesAsync(cancellationToken);

        sessionService.ClearSessionCookie();
        return Result.Ok();
    }

    public async Task<Result> LogoutAllAsync(CancellationToken cancellationToken)
    {
        if (!currentUserAccessor.TryGetUserId(out var userId))
            return Result.Unauthorized();

        var now = DateTime.UtcNow;
        var revoked = await RevokeSessionsAsync(
            dbContext.Sessions.Where(s => s.UserId == userId && s.RevokedAt == null),
            now,
            cancellationToken);

        if (UsesInMemoryProvider() && revoked > 0)
            await dbContext.SaveChangesAsync(cancellationToken);

        sessionService.ClearSessionCookie();
        return Result.Ok();
    }

    private async Task<Result<UserAuthChallenge>> GetOwnActiveChallengeOrUnauthorizedAsync(
        Guid userId,
        Guid challengeId,
        ChallengePurpose purpose,
        DateTime now,
        CancellationToken cancellationToken)
    {
        var result = await authChallengeService.GetActiveChallengeAsync(
            challengeId,
            purpose,
            userId,
            now,
            cancellationToken);

        return result.IsSuccess ? result : Result<UserAuthChallenge>.Unauthorized();
    }

    private async Task<Result<UserAuthChallenge>> GetOwnActiveChallengeOrNotFoundAsync(
        Guid userId,
        Guid challengeId,
        ChallengePurpose purpose,
        DateTime now,
        CancellationToken cancellationToken)
    {
        var result = await authChallengeService.GetActiveChallengeAsync(
            challengeId,
            purpose,
            userId,
            now,
            cancellationToken);

        return result.IsSuccess ? result : Result<UserAuthChallenge>.NotFound();
    }

    private static bool HasMatchingPendingEmail(UserAuthChallenge challenge)
    {
        return !string.IsNullOrWhiteSpace(challenge.User.PendingEmail) &&
               string.Equals(challenge.TargetEmail, challenge.User.PendingEmail, StringComparison.Ordinal);
    }

    private static bool HasMatchingPendingPhone(UserAuthChallenge challenge)
    {
        return !string.IsNullOrWhiteSpace(challenge.User.PendingPhoneE164) &&
               string.Equals(challenge.TargetPhoneE164, challenge.User.PendingPhoneE164, StringComparison.Ordinal);
    }

    private async Task<int> RevokeSessionsAsync(
        IQueryable<Session> sessionsQuery,
        DateTime now,
        CancellationToken cancellationToken)
    {
        if (UsesInMemoryProvider())
        {
            var sessions = await sessionsQuery.ToListAsync(cancellationToken);
            foreach (var session in sessions)
            {
                session.RevokedAt = now;
            }

            return sessions.Count;
        }

        return await sessionsQuery.ExecuteUpdateAsync(
            updates => updates.SetProperty(session => session.RevokedAt, now),
            cancellationToken);
    }

    private bool UsesInMemoryProvider() => dbContext.UsesInMemoryProvider;

    private string? DebugCodeOrNull(string? code)
    {
        if (!_authOptions.ReturnDebugCodes || string.IsNullOrWhiteSpace(code))
            return null;

        return code;
    }
}
