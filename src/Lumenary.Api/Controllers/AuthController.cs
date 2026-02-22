using Lumenary.Api.Contracts.Auth;
using AppAuthModels = Lumenary.Features.Auth.Models;
using Lumenary.Features.Auth.Services;
using Lumenary.Api.Common.Results;
using Lumenary.Api.Security.AnonymousOnly;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace Lumenary.Api.Controllers;

[ApiController]
[Route("api/auth")]
public sealed class AuthController(IAuthService authService) : ControllerBase
{
    [HttpPost("login")]
    [AnonymousOnly]
    [EnableRateLimiting("Auth")]
    public Task<IActionResult> Login([FromBody] LoginRequest request, CancellationToken cancellationToken)
        => authService.LoginAsync(
                new AppAuthModels.LoginRequest(request.Email, request.Password),
                cancellationToken)
            .ToActionResult(static response => new OkObjectResult(new LoginResponse(
                response.ChallengeId,
                response.Code)));

    [HttpPost("login/verify")]
    [AnonymousOnly]
    [EnableRateLimiting("Auth")]
    public Task<IActionResult> LoginVerify([FromBody] LoginVerifyRequest request,
        CancellationToken cancellationToken)
        => authService.LoginVerifyAsync(
            new AppAuthModels.LoginVerifyRequest(request.ChallengeId, request.Code),
            cancellationToken).ToActionResult();

    [HttpPost("register")]
    [AnonymousOnly]
    [EnableRateLimiting("Auth")]
    public Task<IActionResult> Register([FromBody] RegisterRequest request, CancellationToken cancellationToken)
        => authService.RegisterAsync(
                new AppAuthModels.RegisterRequest(
                    request.Name,
                    request.Email,
                    request.Password,
                    request.PhoneE164,
                    request.DateOfBirth),
                cancellationToken)
            .ToActionResult(static response => new OkObjectResult(new RegisterResponse(
                response.ChallengeId,
                response.Code)));

    [HttpPost("register/verify")]
    [AnonymousOnly]
    [EnableRateLimiting("Auth")]
    public Task<IActionResult> RegisterVerify([FromBody] RegisterVerifyRequest request,
        CancellationToken cancellationToken)
        => authService.RegisterVerifyAsync(
            new AppAuthModels.RegisterVerifyRequest(request.ChallengeId, request.Code),
            cancellationToken).ToActionResult();

    [HttpPost("password/reset")]
    [AnonymousOnly]
    [EnableRateLimiting("Auth")]
    public Task<IActionResult> PasswordReset([FromBody] PasswordResetRequest request,
        CancellationToken cancellationToken)
        => authService.PasswordResetAsync(
                new AppAuthModels.PasswordResetRequest(request.Email),
                cancellationToken)
            .ToActionResult(static response => new OkObjectResult(new PasswordResetResponse(
                response.ChallengeId,
                response.Code)));

    [HttpPost("password/reset/verify")]
    [AnonymousOnly]
    [EnableRateLimiting("Auth")]
    public Task<IActionResult> PasswordResetVerify([FromBody] PasswordResetVerifyRequest request,
        CancellationToken cancellationToken)
        => authService.PasswordResetVerifyAsync(
            new AppAuthModels.PasswordResetVerifyRequest(request.ChallengeId, request.Code),
            cancellationToken).ToActionResult();

    [HttpPost("password/reset/change")]
    [AnonymousOnly]
    [EnableRateLimiting("Auth")]
    public Task<IActionResult> PasswordResetChange([FromBody] PasswordResetChangeRequest request,
        CancellationToken cancellationToken)
        => authService.PasswordResetChangeAsync(
            new AppAuthModels.PasswordResetChangeRequest(request.ChallengeId, request.NewPassword),
            cancellationToken).ToActionResult();

    [HttpPost("challenge/resend")]
    [AnonymousOnly]
    [EnableRateLimiting("Auth")]
    public Task<IActionResult> ResendChallengeCode([FromBody] ResendCodeRequest request,
        CancellationToken cancellationToken)
        => authService.ResendChallengeCodeAsync(
                new AppAuthModels.ResendCodeRequest(request.ChallengeId),
                cancellationToken)
            .ToActionResult(static response => new OkObjectResult(new ResendCodeResponse(
                response.ChallengeId,
                response.Code)));
}
