using Lumenary.Api.Common.Results;
using Lumenary.Common.Results;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Infrastructure;

namespace Lumenary.Api.Tests.Common.Results;

public sealed class ResultExtensionsTests
{
    [Theory]
    [MemberData(nameof(NonGenericMappings))]
    public async Task ToActionResult_WhenResultHasKnownStatus_ThenReturnsExpectedActionResult(
        Result result,
        Type expectedType,
        int? expectedStatusCode)
    {
        var actionResult = await Task.FromResult(result).ToActionResult();

        Assert.IsType(expectedType, actionResult);
        Assert.Equal(expectedStatusCode, (actionResult as IStatusCodeActionResult)?.StatusCode);
    }

    [Theory]
    [MemberData(nameof(GenericMappings))]
    public async Task ToActionResultOfT_WhenResultHasKnownStatus_ThenReturnsExpectedActionResult(
        Result<string> result,
        Type expectedType,
        int? expectedStatusCode,
        string? expectedValue)
    {
        var actionResult = await Task.FromResult(result).ToActionResult();

        Assert.IsType(expectedType, actionResult);
        Assert.Equal(expectedStatusCode, (actionResult as IStatusCodeActionResult)?.StatusCode);

        if (actionResult is OkObjectResult okObjectResult)
            Assert.Equal(expectedValue, okObjectResult.Value);
    }

    [Fact]
    public async Task ToActionResultOfTWithOnSuccess_WhenResultIsSuccessfulWithValue_ThenInvokesDelegate()
    {
        var called = 0;
        var expectedResult = new CreatedResult("/api/resource/123", new { id = 123 });

        var actionResult = await Task.FromResult(Result<string>.Ok("payload"))
            .ToActionResult(value =>
            {
                called += 1;
                Assert.Equal("payload", value);
                return expectedResult;
            });

        Assert.Equal(1, called);
        Assert.Same(expectedResult, actionResult);
    }

    [Fact]
    public async Task ToActionResultOfTWithOnSuccess_WhenResultIsSuccessfulWithNullValue_ThenFallsBackToDefaultMapping()
    {
        var called = 0;

        var actionResult = await Task.FromResult(Result<string?>.Ok(null))
            .ToActionResult(_ =>
            {
                called += 1;
                return new OkResult();
            });

        Assert.Equal(0, called);

        var ok = Assert.IsType<OkObjectResult>(actionResult);
        Assert.Null(ok.Value);
    }

    [Fact]
    public async Task ToActionResultOfTWithOnSuccess_WhenResultIsFailure_ThenDoesNotInvokeDelegate()
    {
        var called = 0;

        var actionResult = await Task.FromResult(Result<string>.Unauthorized())
            .ToActionResult(_ =>
            {
                called += 1;
                return new OkResult();
            });

        Assert.Equal(0, called);
        Assert.IsType<UnauthorizedResult>(actionResult);
    }

    public static IEnumerable<object?[]> NonGenericMappings()
    {
        yield return [Result.Ok(), typeof(OkResult), StatusCodes.Status200OK];
        yield return [Result.BadRequest(), typeof(BadRequestResult), StatusCodes.Status400BadRequest];
        yield return [Result.Unauthorized(), typeof(UnauthorizedResult), StatusCodes.Status401Unauthorized];
        yield return [Result.Forbidden(), typeof(ForbidResult), null];
        yield return [Result.NotFound(), typeof(NotFoundResult), StatusCodes.Status404NotFound];
        yield return [Result.Conflict(), typeof(ConflictResult), StatusCodes.Status409Conflict];
        yield return [Result.TooManyRequests(), typeof(StatusCodeResult), StatusCodes.Status429TooManyRequests];
        yield return [Result.ServiceUnavailable(), typeof(StatusCodeResult), StatusCodes.Status503ServiceUnavailable];
    }

    public static IEnumerable<object?[]> GenericMappings()
    {
        yield return [Result<string>.Ok("value"), typeof(OkObjectResult), StatusCodes.Status200OK, "value"];
        yield return [Result<string>.BadRequest(), typeof(BadRequestResult), StatusCodes.Status400BadRequest, null];
        yield return [Result<string>.Unauthorized(), typeof(UnauthorizedResult), StatusCodes.Status401Unauthorized, null];
        yield return [Result<string>.Forbidden(), typeof(ForbidResult), null, null];
        yield return [Result<string>.NotFound(), typeof(NotFoundResult), StatusCodes.Status404NotFound, null];
        yield return [Result<string>.Conflict(), typeof(ConflictResult), StatusCodes.Status409Conflict, null];
        yield return [Result<string>.TooManyRequests(), typeof(StatusCodeResult), StatusCodes.Status429TooManyRequests, null];
        yield return [Result<string>.ServiceUnavailable(), typeof(StatusCodeResult), StatusCodes.Status503ServiceUnavailable, null];
    }
}
