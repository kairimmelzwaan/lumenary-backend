using Microsoft.EntityFrameworkCore;
using Npgsql;

namespace Lumenary.Persistence;

public static class DbUpdateExceptionExtensions
{
    public static bool IsUniqueConstraintViolation(this DbUpdateException exception)
    {
        Exception? current = exception;
        while (current is not null)
        {
            if (current is PostgresException { SqlState: PostgresErrorCodes.UniqueViolation })
                return true;

            current = current.InnerException;
        }

        return false;
    }
}
