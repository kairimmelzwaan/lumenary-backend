using Lumenary.Features.Account.Models;
using Lumenary.Features.Auth.Models;
using Lumenary.Common.Results;

namespace Lumenary.Features.Account.Services;

public interface IAccountService
{
    Task<Result<AccountMeResponse>> GetMeAsync(CancellationToken cancellationToken);
    Task<Result> UpdateProfileAsync(UpdateProfileRequest request, CancellationToken cancellationToken);
    Task<Result> ChangePasswordAsync(PasswordChangeRequest request, CancellationToken cancellationToken);
    Task<Result<ChangeEmailResponse>> ChangeEmailAsync(ChangeEmailRequest request, CancellationToken cancellationToken);
    Task<Result> ChangeEmailVerifyAsync(ChangeEmailVerifyRequest request, CancellationToken cancellationToken);
    Task<Result> ChangeEmailCancelAsync(ChangeEmailCancelRequest request, CancellationToken cancellationToken);
    Task<Result<ChangePhoneResponse>> ChangePhoneAsync(ChangePhoneRequest request, CancellationToken cancellationToken);
    Task<Result> ChangePhoneVerifyAsync(ChangePhoneVerifyRequest request, CancellationToken cancellationToken);
    Task<Result> ChangePhoneCancelAsync(ChangePhoneCancelRequest request, CancellationToken cancellationToken);
    Task<Result<SessionsOverviewResponse>> GetSessionsAsync(CancellationToken cancellationToken);
    Task<Result> LogoutAsync(CancellationToken cancellationToken);
    Task<Result> LogoutAllAsync(CancellationToken cancellationToken);
}
