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
COPY ["src/Cfio.IdentityServer.STS.Identity/Cfio.IdentityServer.STS.Identity.csproj", "src/Cfio.IdentityServer.STS.Identity/"]
COPY ["src/Cfio.IdentityServer.Admin.EntityFramework.Shared/Cfio.IdentityServer.Admin.EntityFramework.Shared.csproj", "src/Cfio.IdentityServer.Admin.EntityFramework.Shared/"]
COPY ["src/Cfio.IdentityServer.Shared/Cfio.IdentityServer.Shared.csproj", "src/Cfio.IdentityServer.Shared/"]
RUN dotnet restore "src/Cfio.IdentityServer.STS.Identity/Cfio.IdentityServer.STS.Identity.csproj"
COPY . .
WORKDIR "/src/src/Cfio.IdentityServer.STS.Identity"
RUN dotnet build "Cfio.IdentityServer.STS.Identity.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "Cfio.IdentityServer.STS.Identity.csproj" -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENV ASPNETCORE_FORWARDEDHEADERS_ENABLED=true
ENTRYPOINT ["dotnet", "Cfio.IdentityServer.STS.Identity.dll"]