using System;
using System.IO;
using System.Reflection;
using System.Runtime.CompilerServices;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Skoruba.AuditLogging.EntityFramework.DbContexts;
using Skoruba.AuditLogging.EntityFramework.Entities;
using Skoruba.Duende.IdentityServer.Admin.EntityFramework.Configuration.Configuration;
using Skoruba.Duende.IdentityServer.Admin.EntityFramework.Helpers;
using Skoruba.Duende.IdentityServer.Admin.EntityFramework.Interfaces;
using Skoruba.Duende.IdentityServer.Admin.UI.Configuration;
using Skoruba.Duende.IdentityServer.Admin.UI.Helpers.ApplicationBuilder;

namespace Cfio.IdentityServer.Admin.Helpers
{
    public static class StartupHelpers
    {
        public static void AddAdminUIRazorRuntimeCompilation(this IServiceCollection services, IWebHostEnvironment hostingEnvironment)
        {
            if (hostingEnvironment.IsDevelopment())
            {
                var builder = services.AddControllersWithViews();

                var adminAssembly = typeof(AdminUIApplicationBuilderExtensions).GetTypeInfo().Assembly.GetName().Name;

                builder.AddRazorRuntimeCompilation(options =>
                {
                    if (adminAssembly == null) return;

                    var libraryPath = Path.GetFullPath(Path.Combine(hostingEnvironment.ContentRootPath, "..", adminAssembly));

                    if (Directory.Exists(libraryPath))
                    {
                        options.FileProviders.Add(new PhysicalFileProvider(libraryPath));
                    }
                });
            }
        }

        public static void AddIdSHealthChecks<TConfigurationDbContext, TPersistedGrantDbContext, TIdentityDbContext, TLogDbContext, TAuditLoggingDbContext, TAuditLog>(this IHealthChecksBuilder healthChecksBuilder, AdminConfiguration adminConfiguration, ConnectionStringsConfiguration connectionStringsConfiguration, DatabaseProviderConfiguration databaseProviderConfiguration) where TConfigurationDbContext : DbContext, IAdminConfigurationDbContext where TPersistedGrantDbContext : DbContext, IAdminPersistedGrantDbContext where TIdentityDbContext : DbContext where TLogDbContext : DbContext, IAdminLogDbContext where TAuditLoggingDbContext : DbContext, IAuditLoggingDbContext<TAuditLog> where TAuditLog : AuditLog
        {
            string configurationDbConnection = connectionStringsConfiguration.ConfigurationDbConnection;
            string persistedGrantDbConnection = connectionStringsConfiguration.PersistedGrantDbConnection;
            string identityDbConnection = connectionStringsConfiguration.IdentityDbConnection;
            string adminLogDbConnection = connectionStringsConfiguration.AdminLogDbConnection;
            string adminAuditLogDbConnection = connectionStringsConfiguration.AdminAuditLogDbConnection;
            string dataProtectionDbConnection = connectionStringsConfiguration.DataProtectionDbConnection;
            string identityServerBaseUrl = adminConfiguration.IdentityServerBaseUrl;
            healthChecksBuilder = healthChecksBuilder.AddDbContextCheck<TConfigurationDbContext>("ConfigurationDbContext").AddDbContextCheck<TPersistedGrantDbContext>("PersistedGrantsDbContext").AddDbContextCheck<TIdentityDbContext>("IdentityDbContext")
                .AddDbContextCheck<TLogDbContext>("LogDbContext")
                .AddDbContextCheck<TAuditLoggingDbContext>("AuditLogDbContext")
                .AddIdentityServer(new Uri(identityServerBaseUrl), "Identity Server");
            using IServiceScope serviceScope = ServiceProviderServiceExtensions.GetRequiredService<IServiceScopeFactory>(healthChecksBuilder.Services.BuildServiceProvider()).CreateScope();
            string entityTable = DbContextHelpers.GetEntityTable<TConfigurationDbContext>(serviceScope.ServiceProvider);
            string entityTable2 = DbContextHelpers.GetEntityTable<TPersistedGrantDbContext>(serviceScope.ServiceProvider);
            string entityTable3 = DbContextHelpers.GetEntityTable<TIdentityDbContext>(serviceScope.ServiceProvider);
            string entityTable4 = DbContextHelpers.GetEntityTable<TLogDbContext>(serviceScope.ServiceProvider);
            string entityTable5 = DbContextHelpers.GetEntityTable<TAuditLoggingDbContext>(serviceScope.ServiceProvider);
            switch (databaseProviderConfiguration.ProviderType)
            {
                case DatabaseProviderType.SqlServer:
                    healthChecksBuilder.AddSqlServer(configurationDbConnection, "SELECT TOP 1 * FROM dbo.[" + entityTable + "]", "ConfigurationDb").AddSqlServer(persistedGrantDbConnection, "SELECT TOP 1 * FROM dbo.[" + entityTable2 + "]", "PersistentGrantsDb").AddSqlServer(identityDbConnection, "SELECT TOP 1 * FROM dbo.[" + entityTable3 + "]", "IdentityDb")
                        .AddSqlServer(adminLogDbConnection, "SELECT TOP 1 * FROM dbo.[" + entityTable4 + "]", "LogDb")
                        .AddSqlServer(adminAuditLogDbConnection, "SELECT TOP 1 * FROM dbo.[" + entityTable5 + "]", "AuditLogDb")
                        ;
                    return;
                case DatabaseProviderType.PostgreSQL:
                    healthChecksBuilder.AddNpgSql(configurationDbConnection, "SELECT * FROM \"" + entityTable + "\" LIMIT 1", null, "ConfigurationDb").AddNpgSql(persistedGrantDbConnection, "SELECT * FROM \"" + entityTable2 + "\" LIMIT 1", null, "PersistentGrantsDb").AddNpgSql(identityDbConnection, "SELECT * FROM \"" + entityTable3 + "\" LIMIT 1", null, "IdentityDb")
                        .AddNpgSql(adminLogDbConnection, "SELECT * FROM \"" + entityTable4 + "\" LIMIT 1", null, "LogDb")
                        .AddNpgSql(adminAuditLogDbConnection, "SELECT * FROM \"" + entityTable5 + "\"  LIMIT 1", null, "AuditLogDb")
                        ;
                    return;
                case DatabaseProviderType.MySql:
                    healthChecksBuilder.AddMySql(configurationDbConnection, "ConfigurationDb").AddMySql(persistedGrantDbConnection, "PersistentGrantsDb").AddMySql(identityDbConnection, "IdentityDb")
                        .AddMySql(adminLogDbConnection, "LogDb")
                        .AddMySql(adminAuditLogDbConnection, "AuditLogDb")
                        ;
                    return;
            }

            DefaultInterpolatedStringHandler defaultInterpolatedStringHandler = new DefaultInterpolatedStringHandler(48, 1);
            defaultInterpolatedStringHandler.AppendLiteral("Health checks not defined for database provider ");
            defaultInterpolatedStringHandler.AppendFormatted(databaseProviderConfiguration.ProviderType);
            throw new NotImplementedException(defaultInterpolatedStringHandler.ToStringAndClear());
        }

    }
}







