using Lumenary.Api.Contracts.Account;
using AppAccountModels = Lumenary.Features.Account.Models;
using Lumenary.Api.Contracts.Auth;
using AppAuthModels = Lumenary.Features.Auth.Models;
using Lumenary.Features.Account.Services;
using Lumenary.Api.Common.Results;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace Lumenary.Api.Controllers;

[ApiController]
[Route("api/account")]
public sealed class AccountController(IAccountService accountService) : ControllerBase
{
    [HttpGet("me")]
    [Authorize]
    public Task<IActionResult> GetMe(CancellationToken cancellationToken)
        => accountService.GetMeAsync(cancellationToken).ToActionResult(static response =>
            new OkObjectResult(new AccountMeResponse(
                response.Name,
                response.Email,
                response.PhoneE164,
                response.DateOfBirth)));

    [HttpPatch]
    [Authorize]
    public Task<IActionResult> UpdateProfile([FromBody] UpdateProfileRequest request,
        CancellationToken cancellationToken)
        => accountService.UpdateProfileAsync(
            new AppAccountModels.UpdateProfileRequest(request.Name, request.DateOfBirth),
            cancellationToken).ToActionResult();

    [HttpPost("password/change")]
    [Authorize]
    public Task<IActionResult> ChangePassword([FromBody] PasswordChangeRequest request,
        CancellationToken cancellationToken)
        => accountService.ChangePasswordAsync(
            new AppAuthModels.PasswordChangeRequest(request.CurrentPassword, request.NewPassword),
            cancellationToken).ToActionResult();

    [HttpPost("email/change")]
    [Authorize]
    [EnableRateLimiting("Auth")]
    public Task<IActionResult> ChangeEmail([FromBody] ChangeEmailRequest request,
        CancellationToken cancellationToken)
        => accountService.ChangeEmailAsync(
                new AppAuthModels.ChangeEmailRequest(request.Email),
                cancellationToken)
            .ToActionResult(static response => new OkObjectResult(new ChangeEmailResponse(
                response.ChallengeId,
                response.Code)));

    [HttpPost("email/change/verify")]
    [Authorize]
    [EnableRateLimiting("Auth")]
    public Task<IActionResult> ChangeEmailVerify(
        [FromBody] ChangeEmailVerifyRequest request,
        CancellationToken cancellationToken)
        => accountService.ChangeEmailVerifyAsync(
            new AppAuthModels.ChangeEmailVerifyRequest(request.ChallengeId, request.Code),
            cancellationToken).ToActionResult();

    [HttpPost("email/change/cancel")]
    [Authorize]
    [EnableRateLimiting("Auth")]
    public Task<IActionResult> ChangeEmailCancel(
        [FromBody] ChangeEmailCancelRequest request,
        CancellationToken cancellationToken)
        => accountService.ChangeEmailCancelAsync(
            new AppAuthModels.ChangeEmailCancelRequest(request.ChallengeId),
            cancellationToken).ToActionResult();

    [HttpPost("phone/change")]
    [Authorize]
    [EnableRateLimiting("Auth")]
    public Task<IActionResult> ChangePhone([FromBody] ChangePhoneRequest request,
        CancellationToken cancellationToken)
        => accountService.ChangePhoneAsync(
                new AppAuthModels.ChangePhoneRequest(request.PhoneE164),
                cancellationToken)
            .ToActionResult(static response => new OkObjectResult(new ChangePhoneResponse(
                response.ChallengeId,
                response.Code)));

    [HttpPost("phone/change/verify")]
    [Authorize]
    [EnableRateLimiting("Auth")]
    public Task<IActionResult> ChangePhoneVerify(
        [FromBody] ChangePhoneVerifyRequest request,
        CancellationToken cancellationToken)
        => accountService.ChangePhoneVerifyAsync(
            new AppAuthModels.ChangePhoneVerifyRequest(request.ChallengeId, request.Code),
            cancellationToken).ToActionResult();

    [HttpPost("phone/change/cancel")]
    [Authorize]
    [EnableRateLimiting("Auth")]
    public Task<IActionResult> ChangePhoneCancel(
        [FromBody] ChangePhoneCancelRequest request,
        CancellationToken cancellationToken)
        => accountService.ChangePhoneCancelAsync(
            new AppAuthModels.ChangePhoneCancelRequest(request.ChallengeId),
            cancellationToken).ToActionResult();

    [HttpGet("sessions")]
    [Authorize]
    public Task<IActionResult> GetSessions(CancellationToken cancellationToken)
        => accountService.GetSessionsAsync(cancellationToken).ToActionResult(static response =>
            new OkObjectResult(new SessionsOverviewResponse(
                response.LastLoginAt,
                response.LastLoginUserAgent,
                response.LastLoginIpAddress,
                response.Sessions
                    .Select(session => new SessionResponse(
                        session.CreatedAt,
                        session.LastSeenAt,
                        session.ExpiresAt,
                        session.UserAgent,
                        session.IpAddress))
                    .ToList())));

    [HttpPost("logout")]
    [Authorize]
    public Task<IActionResult> Logout(CancellationToken cancellationToken)
        => accountService.LogoutAsync(cancellationToken).ToActionResult();

    [HttpPost("logout/all")]
    [Authorize]
    public Task<IActionResult> LogoutAll(CancellationToken cancellationToken)
        => accountService.LogoutAllAsync(cancellationToken).ToActionResult();
}
