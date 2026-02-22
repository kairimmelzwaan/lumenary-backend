using Lumenary.Features.Auth.Models;
using Lumenary.Common.Results;

namespace Lumenary.Features.Auth.Services;

public interface IAuthService
{
    Task<Result<LoginResponse>> LoginAsync(LoginRequest request, CancellationToken cancellationToken);
    Task<Result> LoginVerifyAsync(LoginVerifyRequest request, CancellationToken cancellationToken);
    Task<Result<RegisterResponse>> RegisterAsync(RegisterRequest request, CancellationToken cancellationToken);
    Task<Result> RegisterVerifyAsync(RegisterVerifyRequest request, CancellationToken cancellationToken);
    Task<Result<PasswordResetResponse>> PasswordResetAsync(PasswordResetRequest request, CancellationToken cancellationToken);
    Task<Result> PasswordResetVerifyAsync(PasswordResetVerifyRequest request, CancellationToken cancellationToken);
    Task<Result> PasswordResetChangeAsync(PasswordResetChangeRequest request, CancellationToken cancellationToken);
    Task<Result<ResendCodeResponse>> ResendChallengeCodeAsync(ResendCodeRequest request, CancellationToken cancellationToken);
}
