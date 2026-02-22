namespace Lumenary.Common.Results;

public enum ResultStatus
{
    Ok,
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    TooManyRequests,
    ServiceUnavailable
}

public readonly struct Result
{
    public ResultStatus Status { get; }

    private Result(ResultStatus status)
    {
        Status = status;
    }

    public bool IsSuccess => Status == ResultStatus.Ok;

    public static Result Ok() => new(ResultStatus.Ok);
    public static Result BadRequest() => new(ResultStatus.BadRequest);
    public static Result Unauthorized() => new(ResultStatus.Unauthorized);
    public static Result Forbidden() => new(ResultStatus.Forbidden);
    public static Result NotFound() => new(ResultStatus.NotFound);
    public static Result Conflict() => new(ResultStatus.Conflict);
    public static Result TooManyRequests() => new(ResultStatus.TooManyRequests);
    public static Result ServiceUnavailable() => new(ResultStatus.ServiceUnavailable);
}

public readonly struct Result<T>
{
    public ResultStatus Status { get; }
    public T? Value { get; }

    private Result(ResultStatus status, T? value)
    {
        Status = status;
        Value = value;
    }

    public bool IsSuccess => Status == ResultStatus.Ok;

    public static Result<T> Ok(T value) => new(ResultStatus.Ok, value);
    public static Result<T> BadRequest() => new(ResultStatus.BadRequest, default);
    public static Result<T> Unauthorized() => new(ResultStatus.Unauthorized, default);
    public static Result<T> Forbidden() => new(ResultStatus.Forbidden, default);
    public static Result<T> NotFound() => new(ResultStatus.NotFound, default);
    public static Result<T> Conflict() => new(ResultStatus.Conflict, default);
    public static Result<T> TooManyRequests() => new(ResultStatus.TooManyRequests, default);
    public static Result<T> ServiceUnavailable() => new(ResultStatus.ServiceUnavailable, default);
}
