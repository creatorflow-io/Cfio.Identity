// Copyright (c) Jan Škoruba. All Rights Reserved.
// Licensed under the Apache License, Version 2.0.

using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Cfio.IdentityServer.Admin.EntityFramework.Shared.Constants;
using Cfio.IdentityServer.Admin.EntityFramework.Shared.Entities.Identity;
using Cfio.IdentityServer.Admin.EntityFramework.Shared.Helpers;
using Finbuckle.MultiTenant;
using Finbuckle.MultiTenant.EntityFrameworkCore;
using Juice.Extensions.DependencyInjection;
using Juice.MultiTenant.EF.Extensions;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Cfio.IdentityServer.Admin.EntityFramework.Shared.DbContexts
{
    public class TenantIdentityDbContext : IdentityDbContext<UserIdentity, UserIdentityRole, string, UserIdentityUserClaim, UserIdentityUserRole, UserIdentityUserLogin, UserIdentityRoleClaim, UserIdentityUserToken>, IMultiTenantDbContext

    {
        public TenantIdentityDbContext(DbContextOptions<TenantIdentityDbContext> options, ITenantInfo tenantInfo = null) : base(options)
        {
            TenantInfo = tenantInfo ?? new TenantInfo { Id = "" };
        }

        public ITenantInfo TenantInfo { get; protected set; }

        public TenantMismatchMode TenantMismatchMode => TenantMismatchMode.Throw;

        public TenantNotSetMode TenantNotSetMode => TenantNotSetMode.Throw;

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            builder.ConfigureMultiTenant();

            ConfigureIdentityContext(builder);
        }

        private void ConfigureIdentityContext(ModelBuilder builder)
        {
            builder.Entity<UserIdentityRole>().ToTable(TableConsts.IdentityRoles).IsCrossTenant();

            builder.Entity<UserIdentityRoleClaim>().ToTable(TableConsts.IdentityRoleClaims);
            builder.Entity<UserIdentityUserRole>().ToTable(TableConsts.IdentityUserRoles);

            builder.Entity<UserIdentity>().ToTable(TableConsts.IdentityUsers).IsCrossTenant();

            builder.Entity<UserIdentityUserLogin>().ToTable(TableConsts.IdentityUserLogins);
            builder.Entity<UserIdentityUserClaim>().ToTable(TableConsts.IdentityUserClaims);
            builder.Entity<UserIdentityUserToken>().ToTable(TableConsts.IdentityUserTokens);
        }


        public override int SaveChanges(bool acceptAllChangesOnSuccess)
        {
            this.EnforceMultiTenant();
            return base.SaveChanges(acceptAllChangesOnSuccess);
        }

        public override async Task<int> SaveChangesAsync(bool acceptAllChangesOnSuccess,
                                                         CancellationToken cancellationToken = default(CancellationToken))
        {
            this.EnforceMultiTenant();
            return await base.SaveChangesAsync(acceptAllChangesOnSuccess, cancellationToken);
        }
    }


    public class TenantIdentityDbContextFactory : IDesignTimeDbContextFactory<TenantIdentityDbContext>
    {
        public TenantIdentityDbContext CreateDbContext(string[] args)
        {
            var environment = new ConfigurationBuilder()
                .AddCommandLine(args)
                .Build().GetSection("environment")?.ToString() ?? "Development";

            var resolver = new DependencyResolver
            {
                CurrentDirectory = AppContext.BaseDirectory
            };

            resolver.ConfigureServices(services =>
            {

                // Register DbContext class
                var configuration = new ConfigurationBuilder()
                    .SetBasePath(Directory.GetCurrentDirectory())
                    .AddJsonFile("appsettings.json")
                    .AddJsonFile("identitydata.json", optional: true, reloadOnChange: true)
                    .AddJsonFile($"identitydata.{environment}.json", optional: true, reloadOnChange: true)
                    .AddCommandLine(args)
                 .Build();

                var tenantConfig = new TenantMigrationConfiguration();
                configuration.GetSection("IdentityData:Tenant").Bind(tenantConfig);

                var provider = configuration.GetSection("Provider").Get<string>() ?? "SqlServer";


                services.AddDbContext<TenantIdentityDbContext>(
                   options => _ = provider switch
                   {
                       "PostgreSQL" => options.UseNpgsql(
                           configuration.GetConnectionString("IdentityDbConnection"),
                           x => x.MigrationsAssembly("Cfio.IdentityServer.Admin.EntityFramework.PostgreSQL")),

                       "SqlServer" => options.UseSqlServer(
                           configuration.GetConnectionString("IdentityDbConnection"),
                           x => x.MigrationsAssembly("Cfio.IdentityServer.Admin.EntityFramework.SqlServer")),

                       _ => throw new NotSupportedException($"Unsupported provider: {provider}")
                   });


                services.AddScoped<ITenantInfo>(sp => new TenantInfo
                {
                    Id = tenantConfig.Id,
                    Identifier = tenantConfig.Identifier,
                    Name = tenantConfig.Name
                });
            });

            return resolver.ServiceProvider.GetRequiredService<TenantIdentityDbContext>();
        }
    }

}
