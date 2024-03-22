using System;
using System.IO;
using System.Threading.Tasks;
using Cfio;
using Cfio.IdentityServer.Admin.EntityFramework.Shared.DbContexts;
using Cfio.IdentityServer.Admin.EntityFramework.Shared.Entities.Identity;
using Cfio.IdentityServer.STS.Identity.Helpers;
using Duende.IdentityServer.Configuration;
using Duende.IdentityServer.Extensions;
using HealthChecks.UI.Client;
using Juice.MultiTenant;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Serilog;
using Skoruba.Duende.IdentityServer.Shared.Configuration.Helpers;

var configuration = GetConfiguration(args);
Log.Logger = new LoggerConfiguration()
    .ReadFrom.Configuration(configuration)
    .CreateLogger();
try
{
    DockerHelpers.ApplyDockerConfiguration(configuration);

    var builder = WebApplication.CreateBuilder(args);
    var env = builder.Environment;
    builder.Configuration
        .AddJsonFile("serilog.json", optional: true, reloadOnChange: true)
        .AddJsonFile($"serilog.{env.EnvironmentName}.json", optional: true, reloadOnChange: true)
        ;

    if (env.IsDevelopment())
    {
        builder.Configuration.AddUserSecrets(Cfio.IdentityServer.STS.Identity.Helpers.StartupHelpers.SecretName);
    }

    builder.AddRootConfiguration();
    builder.RegisterDbContexts<TenantIdentityDbContext, IdentityServerConfigurationDbContext, IdentityServerPersistedGrantDbContext, IdentityServerDataProtectionDbContext>();
    builder.ConfigureAuthentication();
    builder.ConfigureAuthorization();
    builder.RegisterHstsOptions();
    builder.ConfigureMultiTenant();
    builder.ConfigureDistributedCache();
    builder.ConfigureDataProtection();
    builder.AddIdSHealthChecks<IdentityServerConfigurationDbContext, IdentityServerPersistedGrantDbContext, TenantIdentityDbContext>();

    builder.Services.AddEmailSenders(builder.Configuration);

    builder.Services.AddScoped<XMiddleware>();

    // Add all dependencies for Asp.Net Core Identity in MVC - these dependencies are injected into generic Controllers
    // Including settings for MVC and Localization
    // If you want to change primary keys or use another db model for Asp.Net Core Identity:
    builder.AddMvcWithLocalization<UserIdentity, string>();

    builder.Host.UseSerilog((hostContext, loggerConfig) =>
    {
        loggerConfig
            .ReadFrom.Configuration(hostContext.Configuration)
            .Enrich.WithProperty("ApplicationName", hostContext.HostingEnvironment.ApplicationName);
    });

    var app = builder.Build();

    app.UseCookiePolicy();

    if (env.IsDevelopment())
    {
        app.UseDeveloperExceptionPage();
    }
    else
    {
        app.UseHsts();
    }

    // Add custom security headers
    app.UseSecurityHeaders(app.Configuration);

    app.UseMultiTenant();

    app.UseStaticFiles();

    app.UseRouting();

    app.UseMiddleware<XMiddleware>();

    app.UseIdentityServer();

    app.UseAuthorization();

    app.UseMvcLocalizationServices();

    app.MapDefaultControllerRoute();
    app.MapHealthChecks("/health", new HealthCheckOptions
    {
        ResponseWriter = UIResponseWriter.WriteHealthCheckUIResponse
    });

    await app.RunAsync();
}
catch (Exception ex)
{
    Log.Fatal(ex, "Host terminated unexpectedly");
}
finally
{
    Log.CloseAndFlush();
}

static IConfiguration GetConfiguration(string[] args)
{
    var environment = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT");
    var isDevelopment = environment == Environments.Development;

    var configurationBuilder = new ConfigurationBuilder()
        .SetBasePath(Directory.GetCurrentDirectory())
        .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
        .AddJsonFile($"appsettings.{environment}.json", optional: true, reloadOnChange: true)
        .AddJsonFile("serilog.json", optional: true, reloadOnChange: true)
        .AddJsonFile($"serilog.{environment}.json", optional: true, reloadOnChange: true);

    if (isDevelopment)
    {
        configurationBuilder.AddUserSecrets(Cfio.IdentityServer.STS.Identity.Helpers.StartupHelpers.SecretName);
    }

    var configuration = configurationBuilder.Build();

    configurationBuilder.AddCommandLine(args);
    configurationBuilder.AddEnvironmentVariables();

    return configurationBuilder.Build();
}

namespace Cfio
{
    class XMiddleware : IMiddleware
    {
        public async Task InvokeAsync(HttpContext context, RequestDelegate next)
        {
            if ((context.Request.Path.Value == "/connect/endsession" && context.Response.StatusCode == 200)
               || (context.Request.Path.Value == "/connect/authorize" && !context.User.IsAuthenticated())
               || (context.Request.Path.Value.Equals("/Account/Logout", StringComparison.OrdinalIgnoreCase) && context.Request.Method == "POST")
               || (context.Request.Path.Value.Equals("/Account/Login", StringComparison.OrdinalIgnoreCase) && context.Request.Method == "GET")
               )
            {
                var tenant = context.RequestServices.GetService<ITenant>();
                if (!string.IsNullOrEmpty(tenant?.Identifier))
                {
                    context.Response.Cookies.Delete(".AspNetCore.Identity.Application");

                    var logger = context.RequestServices.GetService<ILogger<XMiddleware>>();
                    foreach (var cookie in context.Request.Cookies)
                    {
                        if (cookie.Key.StartsWith(".AspNetCore.Antiforgery", StringComparison.OrdinalIgnoreCase))
                        {
                            context.Response.Cookies.Delete(cookie.Key, new CookieOptions { Path = "/" });
                            logger.LogInformation($"Deleted cookie {cookie.Key} for tenant {tenant.Identifier}");
                        }
                    }
                }
            }
            
            await next(context);
           
        }

    }
}
