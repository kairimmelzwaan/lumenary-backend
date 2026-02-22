Lumenary Backend

requirements
- .NET 10.0 sdk
- PostgreSQL

setup
1. configure settings:
    - copy `src/Lumenary.Api/appsettings.template.json` to `src/Lumenary.Api/appsettings.json`.
    - update `ConnectionStrings:Default` and `Auth:SessionTokenKey` to a random generated string.
    - set `AllowedHosts` to your hostnames in non-development environments.
    - optionally set `Cors:AllowedOrigins` if your frontend is on a different origin.
    - set `ForwardedHeaders:KnownProxies` or `ForwardedHeaders:KnownNetworks` when behind a reverse proxy.
    - update `SeedUser` for a local development automatic admin (only used in Development).
2. create the database:
    - `dotnet ef database update --project src/Lumenary.Infrastructure --startup-project src/Lumenary.Api`

run
- `dotnet run --project src/Lumenary.Api`

the api will start with the defaults in `src/Lumenary.Api/appsettings.template.json`.

this program uses Swagger for the time being.

you can find it on `http://localhost:port/swagger/index.html`
