// Copyright (c) Jan Škoruba. All Rights Reserved.
// Licensed under the Apache License, Version 2.0.

using System;
using System.IdentityModel.Tokens.Jwt;
using Cfio.IdentityServer.Admin.Configuration.Database;
using Cfio.IdentityServer.Admin.EntityFramework.Shared.DbContexts;
using Cfio.IdentityServer.Admin.EntityFramework.Shared.Entities.Identity;
using Cfio.IdentityServer.Admin.Helpers;
using Cfio.IdentityServer.Shared.Dtos;
using Cfio.IdentityServer.Shared.Dtos.Identity;
using Finbuckle.MultiTenant;
using Juice.AspNetCore;
using Juice.Domain;
using Juice.MultiTenant;
using Juice.MultiTenant.AspNetCore;
using Juice.MultiTenant.EF;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.EntityFrameworkCore;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Skoruba.AuditLogging.EntityFramework.DbContexts;
using Skoruba.AuditLogging.EntityFramework.Entities;
using Skoruba.Duende.IdentityServer.Admin.BusinessLogic.Extensions;
using Skoruba.Duende.IdentityServer.Admin.BusinessLogic.Identity.Dtos.Identity;
using Skoruba.Duende.IdentityServer.Admin.BusinessLogic.Identity.Extensions;
using Skoruba.Duende.IdentityServer.Admin.EntityFramework.Interfaces;
using Skoruba.Duende.IdentityServer.Admin.UI.Configuration;
using Skoruba.Duende.IdentityServer.Admin.UI.Helpers;
using Skoruba.Duende.IdentityServer.Admin.UI.Helpers.ApplicationBuilder;
using Skoruba.Duende.IdentityServer.Admin.UI.Helpers.DependencyInjection;
using Skoruba.Duende.IdentityServer.Shared.Configuration.Helpers;
using StackExchange.Redis;
using static Juice.MultiTenant.AspNetCore.AuthenticationFinbuckleMultiTenantBuilderExtensions;

namespace Cfio.IdentityServer.Admin
{
    public class Startup
    {
        public Startup(IWebHostEnvironment env, IConfiguration configuration)
        {
            JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();
            HostingEnvironment = env;
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        public IWebHostEnvironment HostingEnvironment { get; }

        public void ConfigureServices(IServiceCollection services)
        {
            // Adds the Duende IdentityServer Admin UI with custom options.
            AddIdentityServerAdminUI<TenantIdentityDbContext, IdentityServerConfigurationDbContext, IdentityServerPersistedGrantDbContext,
            AdminLogDbContext, AdminAuditLogDbContext, AuditLog, IdentityServerDataProtectionDbContext,
                UserIdentity, UserIdentityRole, UserIdentityUserClaim, UserIdentityUserRole,
                UserIdentityUserLogin, UserIdentityRoleClaim, UserIdentityUserToken, string,
                IdentityUserDto, IdentityRoleDto, IdentityUsersDto, IdentityRolesDto, IdentityUserRolesDto,
                IdentityUserClaimsDto, IdentityUserProviderDto, IdentityUserProvidersDto, IdentityUserChangePasswordDto,
                IdentityRoleClaimsDto, IdentityUserClaimDto, IdentityRoleClaimDto>(services, ConfigureUIOptions);

            // Monitor changes in Admin UI views
            services.AddAdminUIRazorRuntimeCompilation(HostingEnvironment);

            // Add email senders which is currently setup for SendGrid and SMTP
            services.AddEmailSenders(Configuration);

            ConfigureMultiTenant(services, Configuration, HostingEnvironment);
            ConfigureDataProtection(services, Configuration);
            ConfigureDistributedCache(services, Configuration);
            services.AddDistributedCacheTicketStore();
        }

        public void Configure(IApplicationBuilder app)
        {

            app.UseMultiTenant();

            app.UseCommonMiddleware(ServiceProviderServiceExtensions.GetRequiredService<SecurityConfiguration>(app.ApplicationServices), ServiceProviderServiceExtensions.GetRequiredService<HttpConfiguration>(app.ApplicationServices));

            app.UseRouting();

            app.UseIdentityServerAdminUI();

            app.UseEndpoints(endpoint =>
            {
                endpoint.MapIdentityServerAdminUI();
                endpoint.MapIdentityServerAdminUIHealthChecks();
            });
        }

        public virtual void ConfigureUIOptions(IdentityServerAdminUIOptions options)
        {
            // Applies configuration from appsettings.
            options.BindConfiguration(Configuration);
            if (HostingEnvironment.IsDevelopment())
            {
                options.Security.UseDeveloperExceptionPage = true;
            }
            else
            {
                options.Security.UseHsts = true;
            }

            // Set migration assembly for application of db migrations
            var migrationsAssembly = MigrationAssemblyConfiguration.GetMigrationAssemblyByProvider(options.DatabaseProvider);
            options.DatabaseMigrations.SetMigrationsAssemblies(migrationsAssembly);

            // Use production DbContexts and auth services.
            options.Testing.IsStaging = false;
        }


        private static void ConfigureMultiTenant(IServiceCollection services, IConfiguration configuration, IHostEnvironment environment)
        {
            var authority = configuration.GetSection("AdminConfiguration:IdentityServerBaseUrl").Value;

            services
            .AddMultiTenant()
            .WithBasePathStrategy(options => options.RebaseAspNetCorePathBase = true)
            .ConfigureTenantEFDirectly(configuration, options =>
            {
                options.DatabaseProvider = "PostgreSQL";
                options.ConnectionName = "TenantDbConnection";
                options.Schema = "App";
            }, environment.EnvironmentName)
            .WithPerTenantOptions<OpenIdConnectOptions>((options, tc) =>
            {
                options.Authority = authority + $"/{tc.Identifier}";
            })
            .WithPerTenantAuthenticationCore()
            .WithPerTenantAuthenticationConventions(crossTenantAuthorize: (authTenant, currentTenant, principal) =>
                authTenant == null // root tenant
                && (principal?.Identity?.IsAuthenticated ?? false) // authenticated
                && principal.IsInRole("admin"))
            .WithRemoteAuthenticationCallbackStrategy()
            ;

        }

        private static void AddIdentityServerAdminUI<TIdentityDbContext, TIdentityServerDbContext, TPersistedGrantDbContext, TLogDbContext, TAuditLogDbContext, TAuditLog, TDataProtectionDbContext, TUser, TRole, TUserClaim, TUserRole, TUserLogin, TRoleClaim, TUserToken, TKey, TUserDto, TRoleDto, TUsersDto, TRolesDto, TUserRolesDto, TUserClaimsDto, TUserProviderDto, TUserProvidersDto, TUserChangePasswordDto, TRoleClaimsDto, TUserClaimDto, TRoleClaimDto>(IServiceCollection services, Action<IdentityServerAdminUIOptions> optionsAction) where TIdentityDbContext : IdentityDbContext<TUser, TRole, TKey, TUserClaim, TUserRole, TUserLogin, TRoleClaim, TUserToken> where TIdentityServerDbContext : DbContext, IAdminConfigurationDbContext where TPersistedGrantDbContext : DbContext, IAdminPersistedGrantDbContext where TLogDbContext : DbContext, IAdminLogDbContext where TAuditLogDbContext : DbContext, IAuditLoggingDbContext<TAuditLog> where TAuditLog : AuditLog, new() where TDataProtectionDbContext : DbContext, IDataProtectionKeyContext where TUser : IdentityUser<TKey> where TRole : IdentityRole<TKey> where TUserClaim : IdentityUserClaim<TKey> where TUserRole : IdentityUserRole<TKey> where TUserLogin : IdentityUserLogin<TKey> where TRoleClaim : IdentityRoleClaim<TKey> where TUserToken : IdentityUserToken<TKey> where TKey : IEquatable<TKey> where TUserDto : UserDto<TKey>, new() where TRoleDto : RoleDto<TKey>, new() where TUsersDto : UsersDto<TUserDto, TKey> where TRolesDto : RolesDto<TRoleDto, TKey> where TUserRolesDto : UserRolesDto<TRoleDto, TKey> where TUserClaimsDto : UserClaimsDto<TUserClaimDto, TKey> where TUserProviderDto : UserProviderDto<TKey> where TUserProvidersDto : UserProvidersDto<TUserProviderDto, TKey> where TUserChangePasswordDto : UserChangePasswordDto<TKey> where TRoleClaimsDto : RoleClaimsDto<TRoleClaimDto, TKey> where TUserClaimDto : UserClaimDto<TKey> where TRoleClaimDto : RoleClaimDto<TKey>
        {
            IdentityServerAdminUIOptions options = new IdentityServerAdminUIOptions();
            optionsAction(options);
            services.AddSingleton(options.Admin);
            services.AddSingleton(options.IdentityServerData);
            services.AddSingleton(options.IdentityData);

            options.ConnectionStrings.DataProtectionDbConnection = null;
            if (!options.Testing.IsStaging)
            {
                services.RegisterDbContexts<TIdentityDbContext, TIdentityServerDbContext, TPersistedGrantDbContext, TLogDbContext, TAuditLogDbContext, TDataProtectionDbContext, TAuditLog>(options.ConnectionStrings, options.DatabaseProvider, options.DatabaseMigrations);
            }
            else
            {
                services.RegisterDbContextsStaging<TIdentityDbContext, TIdentityServerDbContext, TPersistedGrantDbContext, TLogDbContext, TAuditLogDbContext, TDataProtectionDbContext, TAuditLog>();
            }

            if (!options.Testing.IsStaging)
            {
                services.AddAuthenticationServices<TIdentityDbContext, TUser, TRole>(options.Admin, options.IdentityConfigureAction, options.Security.AuthenticationBuilderAction);
            }
            else
            {
                services.AddAuthenticationServicesStaging<TIdentityDbContext, TUser, TRole>();
            }

            if (options.Security.UseHsts)
            {
                services.AddHsts(delegate (HstsOptions opt)
                {
                    opt.Preload = true;
                    opt.IncludeSubDomains = true;
                    opt.MaxAge = TimeSpan.FromDays(365.0);
                    options.Security.HstsConfigureAction?.Invoke(opt);
                });
            }

            services.AddMvcExceptionFilters();
            services.AddAdminServices<TIdentityServerDbContext, TPersistedGrantDbContext, TLogDbContext>();
            services.AddAdminAspNetIdentityServices<TIdentityDbContext, TPersistedGrantDbContext, TUserDto, TRoleDto, TUser, TRole, TKey, TUserClaim, TUserRole, TUserLogin, TRoleClaim, TUserToken, TUsersDto, TRolesDto, TUserRolesDto, TUserClaimsDto, TUserProviderDto, TUserProvidersDto, TUserChangePasswordDto, TRoleClaimsDto, TUserClaimDto, TRoleClaimDto>();
            services.AddMvcWithLocalization<TUserDto, TRoleDto, TUser, TRole, TKey, TUserClaim, TUserRole, TUserLogin, TRoleClaim, TUserToken, TUsersDto, TRolesDto, TUserRolesDto, TUserClaimsDto, TUserProviderDto, TUserProvidersDto, TUserChangePasswordDto, TRoleClaimsDto, TUserClaimDto, TRoleClaimDto>(options.Culture);

            services.AddAuthorizationPolicies(options.Admin, options.Security.AuthorizationConfigureAction);
            //var adminConfiguration = options.Admin;
            //var authorizationAction = options.Security.AuthorizationConfigureAction;
            //services.AddAuthorization(delegate (AuthorizationOptions options)
            //{
            //    options.AddPolicy("RequireAdministratorRole", delegate (AuthorizationPolicyBuilder policy)
            //    {
            //        policy.RequireRole(adminConfiguration.AdministrationRole, "tenant_" + adminConfiguration.AdministrationRole);
            //    });
            //    authorizationAction?.Invoke(options);
            //});


            services.AddAuditEventLogging<TAuditLogDbContext, TAuditLog>(options.AuditLogging);
            (options.HealthChecksBuilderFactory?.Invoke(services) ?? services.AddHealthChecks()).AddIdSHealthChecks<TIdentityServerDbContext, TPersistedGrantDbContext, TIdentityDbContext, TLogDbContext, TAuditLogDbContext, TAuditLog>(options.Admin, options.ConnectionStrings, options.DatabaseProvider);
            services.AddSingleton(options.Testing);
            services.AddSingleton(options.Security);
            services.AddSingleton(options.Http);
        }

        private void ConfigureDataProtection(IServiceCollection services, IConfiguration configuration)
        {

            var redis = ConnectionMultiplexer.Connect(configuration.GetConnectionString("Redis"));
            services.AddDataProtection()
                .PersistKeysToStackExchangeRedis(redis);

        }

        private void ConfigureDistributedCache(IServiceCollection services, IConfiguration configuration)
        {
            services.AddStackExchangeRedisCache(options =>
            {
                options.Configuration = configuration.GetConnectionString("Redis");
                options.InstanceName = "sts-admin";
            });
        }

    }

}







