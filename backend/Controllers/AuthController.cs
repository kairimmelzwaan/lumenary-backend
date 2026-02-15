using backend.Dtos;
using backend.Services.Auth;
using backend.Auth.AnonymousOnly;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace backend.Controllers;

[ApiController]
[Route("api/account")]
public sealed class AuthController(IAuthService authService) : ControllerBase
{
    [HttpPost("login")]
    [AnonymousOnly]
    [EnableRateLimiting("Auth")]
    public Task<IActionResult> Login([FromBody] LoginRequest request, CancellationToken cancellationToken)
        => authService.LoginAsync(request, cancellationToken).ToActionResult();

    [HttpPost("login/verify")]
    [AnonymousOnly]
    [EnableRateLimiting("Auth")]
    public Task<IActionResult> LoginVerify([FromBody] LoginVerifyRequest request,
        CancellationToken cancellationToken)
        => authService.LoginVerifyAsync(request, cancellationToken).ToActionResult();

    [HttpPost("register")]
    [AnonymousOnly]
    [EnableRateLimiting("Auth")]
    public Task<IActionResult> Register([FromBody] RegisterRequest request, CancellationToken cancellationToken)
        => authService.RegisterAsync(request, cancellationToken).ToActionResult();

    [HttpPost("register/verify")]
    [AnonymousOnly]
    [EnableRateLimiting("Auth")]
    public Task<IActionResult> RegisterVerify([FromBody] RegisterVerifyRequest request,
        CancellationToken cancellationToken)
        => authService.RegisterVerifyAsync(request, cancellationToken).ToActionResult();

    [HttpPost("password/reset")]
    [AnonymousOnly]
    [EnableRateLimiting("Auth")]
    public Task<IActionResult> PasswordReset([FromBody] PasswordResetRequest request,
        CancellationToken cancellationToken)
        => authService.PasswordResetAsync(request, cancellationToken).ToActionResult();

    [HttpPost("password/reset/verify")]
    [AnonymousOnly]
    [EnableRateLimiting("Auth")]
    public Task<IActionResult> PasswordResetVerify([FromBody] PasswordResetVerifyRequest request,
        CancellationToken cancellationToken)
        => authService.PasswordResetVerifyAsync(request, cancellationToken).ToActionResult();

    [HttpPost("challenge/resend")]
    [AnonymousOnly]
    [EnableRateLimiting("Auth")]
    public Task<IActionResult> ResendChallengeCode([FromBody] ResendCodeRequest request,
        CancellationToken cancellationToken)
        => authService.ResendChallengeCodeAsync(request, cancellationToken).ToActionResult();
}
