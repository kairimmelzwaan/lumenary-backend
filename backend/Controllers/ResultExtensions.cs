using backend.Services.Results;
using Microsoft.AspNetCore.Mvc;

namespace backend.Controllers;

public static class ResultExtensions
{
    private static IActionResult ToActionResult(this Result result)
    {
        return result.Status switch
        {
            ResultStatus.Ok => new OkResult(),
            ResultStatus.BadRequest => new BadRequestResult(),
            ResultStatus.Unauthorized => new UnauthorizedResult(),
            ResultStatus.Forbidden => new ForbidResult(),
            ResultStatus.NotFound => new NotFoundResult(),
            ResultStatus.Conflict => new ConflictResult(),
            ResultStatus.TooManyRequests => new StatusCodeResult(StatusCodes.Status429TooManyRequests),
            ResultStatus.ServiceUnavailable => new StatusCodeResult(StatusCodes.Status503ServiceUnavailable),
            _ => new StatusCodeResult(StatusCodes.Status500InternalServerError)
        };
    }

    public static IActionResult ToActionResult<T>(this Result<T> result)
    {
        return result.Status switch
        {
            ResultStatus.Ok => new OkObjectResult(result.Value),
            ResultStatus.BadRequest => new BadRequestResult(),
            ResultStatus.Unauthorized => new UnauthorizedResult(),
            ResultStatus.Forbidden => new ForbidResult(),
            ResultStatus.NotFound => new NotFoundResult(),
            ResultStatus.Conflict => new ConflictResult(),
            ResultStatus.TooManyRequests => new StatusCodeResult(StatusCodes.Status429TooManyRequests),
            ResultStatus.ServiceUnavailable => new StatusCodeResult(StatusCodes.Status503ServiceUnavailable),
            _ => new StatusCodeResult(StatusCodes.Status500InternalServerError)
        };
    }

    public static async Task<IActionResult> ToActionResult(this Task<Result> task)
        => (await task).ToActionResult();

    public static async Task<IActionResult> ToActionResult<T>(this Task<Result<T>> task)
        => (await task).ToActionResult();

    public static async Task<IActionResult> ToActionResult<T>(
        this Task<Result<T>> task,
        Func<T, IActionResult> onSuccess)
    {
        var result = await task;
        if (result.IsSuccess && result.Value is not null)
            return onSuccess(result.Value);

        return result.ToActionResult();
    }
}
