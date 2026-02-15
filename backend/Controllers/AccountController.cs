using backend.Dtos;
using backend.Services.Account;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace backend.Controllers;

[ApiController]
[Route("api/account")]
public sealed class AccountController(IAccountService accountService) : ControllerBase
{
    [HttpGet("me")]
    [Authorize]
    public Task<IActionResult> GetMe(CancellationToken cancellationToken)
        => accountService.GetMeAsync(cancellationToken).ToActionResult();

    [HttpPatch]
    [Authorize]
    public Task<IActionResult> UpdateProfile([FromBody] UpdateProfileRequest request,
        CancellationToken cancellationToken)
        => accountService.UpdateProfileAsync(request, cancellationToken).ToActionResult();

    [HttpPost("password/change")]
    [Authorize]
    public Task<IActionResult> ChangePassword([FromBody] PasswordChangeRequest request,
        CancellationToken cancellationToken)
        => accountService.ChangePasswordAsync(request, cancellationToken).ToActionResult();

    [HttpPost("email/change")]
    [Authorize]
    [EnableRateLimiting("Auth")]
    public Task<IActionResult> ChangeEmail([FromBody] ChangeEmailRequest request,
        CancellationToken cancellationToken)
        => accountService.ChangeEmailAsync(request, cancellationToken).ToActionResult();

    [HttpPost("email/change/verify")]
    [Authorize]
    [EnableRateLimiting("Auth")]
    public Task<IActionResult> ChangeEmailVerify(
        [FromBody] ChangeEmailVerifyRequest request,
        CancellationToken cancellationToken)
        => accountService.ChangeEmailVerifyAsync(request, cancellationToken).ToActionResult();

    [HttpPost("email/change/cancel")]
    [Authorize]
    [EnableRateLimiting("Auth")]
    public Task<IActionResult> ChangeEmailCancel(
        [FromBody] ChangeEmailCancelRequest request,
        CancellationToken cancellationToken)
        => accountService.ChangeEmailCancelAsync(request, cancellationToken).ToActionResult();

    [HttpPost("phone/change")]
    [Authorize]
    [EnableRateLimiting("Auth")]
    public Task<IActionResult> ChangePhone([FromBody] ChangePhoneRequest request,
        CancellationToken cancellationToken)
        => accountService.ChangePhoneAsync(request, cancellationToken).ToActionResult();

    [HttpPost("phone/change/verify")]
    [Authorize]
    [EnableRateLimiting("Auth")]
    public Task<IActionResult> ChangePhoneVerify(
        [FromBody] ChangePhoneVerifyRequest request,
        CancellationToken cancellationToken)
        => accountService.ChangePhoneVerifyAsync(request, cancellationToken).ToActionResult();

    [HttpPost("phone/change/cancel")]
    [Authorize]
    [EnableRateLimiting("Auth")]
    public Task<IActionResult> ChangePhoneCancel(
        [FromBody] ChangePhoneCancelRequest request,
        CancellationToken cancellationToken)
        => accountService.ChangePhoneCancelAsync(request, cancellationToken).ToActionResult();

    [HttpGet("sessions")]
    [Authorize]
    public Task<IActionResult> GetSessions(CancellationToken cancellationToken)
        => accountService.GetSessionsAsync(cancellationToken).ToActionResult();

    [HttpPost("logout")]
    [Authorize]
    public Task<IActionResult> Logout(CancellationToken cancellationToken)
        => accountService.LogoutAsync(cancellationToken).ToActionResult();

    [HttpPost("logout/all")]
    [Authorize]
    public Task<IActionResult> LogoutAll(CancellationToken cancellationToken)
        => accountService.LogoutAllAsync(cancellationToken).ToActionResult();
}
