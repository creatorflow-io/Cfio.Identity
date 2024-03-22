FROM mcr.microsoft.com/dotnet/aspnet:6.0 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/sdk:6.0 AS build
ARG JuiceRefVersion=7.0.3-alpha.*
ARG GITHUB_PACKAGE_USERNAME
ARG GITHUB_PACKAGE_TOKEN
WORKDIR /src
COPY ["nuget.config", "."]
COPY ["Directory.Build.props", "."]
COPY ["src/Cfio.IdentityServer.Admin/Cfio.IdentityServer.Admin.csproj", "src/Cfio.IdentityServer.Admin/"]
COPY ["src/Cfio.IdentityServer.Admin.EntityFramework.Shared/Cfio.IdentityServer.Admin.EntityFramework.Shared.csproj", "src/Cfio.IdentityServer.Admin.EntityFramework.Shared/"]
COPY ["src/Cfio.IdentityServer.Admin.EntityFramework.SqlServer/Cfio.IdentityServer.Admin.EntityFramework.SqlServer.csproj", "src/Cfio.IdentityServer.Admin.EntityFramework.SqlServer/"]
COPY ["src/Cfio.IdentityServer.Shared/Cfio.IdentityServer.Shared.csproj", "src/Cfio.IdentityServer.Shared/"]
COPY ["src/Cfio.IdentityServer.Admin.EntityFramework.PostgreSQL/Cfio.IdentityServer.Admin.EntityFramework.PostgreSQL.csproj", "src/Cfio.IdentityServer.Admin.EntityFramework.PostgreSQL/"]
COPY ["src/Cfio.IdentityServer.Admin.EntityFramework.MySql/Cfio.IdentityServer.Admin.EntityFramework.MySql.csproj", "src/Cfio.IdentityServer.Admin.EntityFramework.MySql/"]
RUN dotnet restore "src/Cfio.IdentityServer.Admin/Cfio.IdentityServer.Admin.csproj"
COPY . .
WORKDIR "/src/src/Cfio.IdentityServer.Admin"
RUN dotnet build "Cfio.IdentityServer.Admin.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "Cfio.IdentityServer.Admin.csproj" -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENV ASPNETCORE_FORWARDEDHEADERS_ENABLED=true
ENTRYPOINT ["dotnet", "Cfio.IdentityServer.Admin.dll"]