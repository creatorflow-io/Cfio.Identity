// Copyright (c) Jan Škoruba. All Rights Reserved.
// Licensed under the Apache License, Version 2.0.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Threading.Tasks;
using Cfio.IdentityServer.Admin.EntityFramework.Shared.DbContexts;
using Cfio.IdentityServer.Admin.EntityFramework.Shared.Entities.Identity;
using Cfio.IdentityServer.STS.Identity.Configuration;
using Cfio.IdentityServer.STS.Identity.Configuration.ApplicationParts;
using Cfio.IdentityServer.STS.Identity.Configuration.Constants;
using Cfio.IdentityServer.STS.Identity.Configuration.Interfaces;
using Cfio.IdentityServer.STS.Identity.Helpers.Localization;
using Cfio.IdentityServer.STS.Identity.Services;
using Duende.IdentityServer.Configuration;
using Duende.IdentityServer.EntityFramework.Storage;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Validation;
using Finbuckle.MultiTenant;
using Juice.AspNetCore;
using Juice.Domain;
using Juice.Extensions.Options;
using Juice.MultiTenant;
//using Juice.MultiTenant.AspNetCore;
using Juice.MultiTenant.EF;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.EntityFrameworkCore;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Localization;
using Microsoft.AspNetCore.Mvc.Razor;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Skoruba.Duende.IdentityServer.Admin.EntityFramework.Configuration.Configuration;
using Skoruba.Duende.IdentityServer.Admin.EntityFramework.Configuration.MySql;
using Skoruba.Duende.IdentityServer.Admin.EntityFramework.Configuration.PostgreSQL;
using Skoruba.Duende.IdentityServer.Admin.EntityFramework.Configuration.SqlServer;
using Skoruba.Duende.IdentityServer.Admin.EntityFramework.Helpers;
using Skoruba.Duende.IdentityServer.Admin.EntityFramework.Interfaces;
using Skoruba.Duende.IdentityServer.Shared.Configuration.Authentication;
using Skoruba.Duende.IdentityServer.Shared.Configuration.Configuration.Identity;
using StackExchange.Redis;
using static Juice.MultiTenant.AspNetCore.AuthenticationFinbuckleMultiTenantBuilderExtensions;

namespace Cfio.IdentityServer.STS.Identity.Helpers
{
    public static class StartupHelpers
    {
        public const string SecretName = "cfio_is_identity";

        /// <summary>
        /// Register services for MVC and localization including available languages
        /// </summary>
        /// <param name="services"></param>
        public static IMvcBuilder AddMvcWithLocalization<TUser, TKey>(this WebApplicationBuilder builder)
            where TUser : IdentityUser<TKey>
            where TKey : IEquatable<TKey>
        {
            var services = builder.Services;
            var configuration = builder.Configuration;
            services.AddLocalization(opts => { opts.ResourcesPath = ConfigurationConsts.ResourcesPath; });

            services.TryAddTransient(typeof(IGenericControllerLocalizer<>), typeof(GenericControllerLocalizer<>));

            var mvcBuilder = services.AddControllersWithViews(o =>
                {
                    o.Conventions.Add(new GenericControllerRouteConvention());
                })
                .AddViewLocalization(
                    LanguageViewLocationExpanderFormat.Suffix,
                    opts => { opts.ResourcesPath = ConfigurationConsts.ResourcesPath; })
                .AddDataAnnotationsLocalization()
                .ConfigureApplicationPartManager(m =>
                {
                    m.FeatureProviders.Add(new GenericTypeControllerFeatureProvider<TUser, TKey>());
                });

            var cultureConfiguration = configuration.GetSection(nameof(CultureConfiguration)).Get<CultureConfiguration>();
            services.Configure<RequestLocalizationOptions>(
                opts =>
                {
                    // If cultures are specified in the configuration, use them (making sure they are among the available cultures),
                    // otherwise use all the available cultures
                    var supportedCultureCodes = (cultureConfiguration?.Cultures?.Count > 0 ?
                        cultureConfiguration.Cultures.Intersect(CultureConfiguration.AvailableCultures) :
                        CultureConfiguration.AvailableCultures).ToArray();

                    if (!supportedCultureCodes.Any()) supportedCultureCodes = CultureConfiguration.AvailableCultures;
                    var supportedCultures = supportedCultureCodes.Select(c => new CultureInfo(c)).ToList();

                    // If the default culture is specified use it, otherwise use CultureConfiguration.DefaultRequestCulture ("en")
                    var defaultCultureCode = string.IsNullOrEmpty(cultureConfiguration?.DefaultCulture) ?
                        CultureConfiguration.DefaultRequestCulture : cultureConfiguration?.DefaultCulture;

                    // If the default culture is not among the supported cultures, use the first supported culture as default
                    if (!supportedCultureCodes.Contains(defaultCultureCode)) defaultCultureCode = supportedCultureCodes.FirstOrDefault();

                    opts.DefaultRequestCulture = new RequestCulture(defaultCultureCode);
                    opts.SupportedCultures = supportedCultures;
                    opts.SupportedUICultures = supportedCultures;
                });

            return mvcBuilder;
        }

        /// <summary>
        /// Using of Forwarded Headers and Referrer Policy
        /// </summary>
        /// <param name="app"></param>
        /// <param name="configuration"></param>
        public static void UseSecurityHeaders(this IApplicationBuilder app, IConfiguration configuration)
        {
            var forwardingOptions = new ForwardedHeadersOptions()
            {
                ForwardedHeaders = ForwardedHeaders.All
            };

            forwardingOptions.KnownNetworks.Clear();
            forwardingOptions.KnownProxies.Clear();

            app.UseForwardedHeaders(forwardingOptions);

            app.UseReferrerPolicy(options => options.NoReferrer());

            // CSP Configuration to be able to use external resources
            var cspTrustedDomains = new List<string>();
            configuration.GetSection(ConfigurationConsts.CspTrustedDomainsKey).Bind(cspTrustedDomains);
            if (cspTrustedDomains.Any())
            {
                app.UseCsp(csp =>
                {
                    var imagesSources = new List<string> { "data:" };
                    imagesSources.AddRange(cspTrustedDomains);

                    csp.ImageSources(options =>
                    {
                        options.SelfSrc = true;
                        options.CustomSources = imagesSources;
                        options.Enabled = true;
                    });
                    csp.FontSources(options =>
                    {
                        options.SelfSrc = true;
                        options.CustomSources = cspTrustedDomains;
                        options.Enabled = true;
                    });
                    csp.ScriptSources(options =>
                    {
                        options.SelfSrc = true;
                        options.CustomSources = cspTrustedDomains;
                        options.Enabled = true;
                        options.UnsafeInlineSrc = true;
                    });
                    csp.StyleSources(options =>
                    {
                        options.SelfSrc = true;
                        options.CustomSources = cspTrustedDomains;
                        options.Enabled = true;
                        options.UnsafeInlineSrc = true;
                    });
                    csp.Sandbox(options =>
                    {
                        options.AllowForms()
                            .AllowSameOrigin()
                            .AllowScripts();
                    });
                    csp.FrameAncestors(option =>
                    {
                        option.NoneSrc = true;
                        option.Enabled = true;
                    });

                    csp.BaseUris(options =>
                    {
                        options.SelfSrc = true;
                        options.Enabled = true;
                    });

                    csp.ObjectSources(options =>
                    {
                        options.NoneSrc = true;
                        options.Enabled = true;
                    });

                    csp.DefaultSources(options =>
                    {
                        options.Enabled = true;
                        options.SelfSrc = true;
                        options.CustomSources = cspTrustedDomains;
                    });
                });
            }

        }

        /// <summary>
        /// Register DbContexts for IdentityServer ConfigurationStore, PersistedGrants, Identity and DataProtection
        /// Configure the connection strings in AppSettings.json
        /// </summary>
        /// <typeparam name="TConfigurationDbContext"></typeparam>
        /// <typeparam name="TPersistedGrantDbContext"></typeparam>
        /// <typeparam name="TIdentityDbContext"></typeparam>
        /// <typeparam name="TDataProtectionDbContext"></typeparam>
        /// <param name="services"></param>
        /// <param name="configuration"></param>
        public static void RegisterDbContexts<TIdentityDbContext, TConfigurationDbContext, TPersistedGrantDbContext, TDataProtectionDbContext>(this WebApplicationBuilder builder)
            where TIdentityDbContext : DbContext
            where TPersistedGrantDbContext : DbContext, IAdminPersistedGrantDbContext
            where TConfigurationDbContext : DbContext, IAdminConfigurationDbContext
            where TDataProtectionDbContext : DbContext, IDataProtectionKeyContext
        {
            var services = builder.Services;
            var configuration = builder.Configuration;

            var databaseProvider = configuration.GetSection(nameof(DatabaseProviderConfiguration)).Get<DatabaseProviderConfiguration>();

            var identityConnectionString = configuration.GetConnectionString(ConfigurationConsts.IdentityDbConnectionStringKey);
            var configurationConnectionString = configuration.GetConnectionString(ConfigurationConsts.ConfigurationDbConnectionStringKey);
            var persistedGrantsConnectionString = configuration.GetConnectionString(ConfigurationConsts.PersistedGrantDbConnectionStringKey);
            var dataProtectionConnectionString = default(string);

            switch (databaseProvider.ProviderType)
            {
                case DatabaseProviderType.SqlServer:
                    services.RegisterSqlServerDbContexts<TIdentityDbContext, TConfigurationDbContext, TPersistedGrantDbContext, TDataProtectionDbContext>(identityConnectionString, configurationConnectionString, persistedGrantsConnectionString, dataProtectionConnectionString);
                    break;
                case DatabaseProviderType.PostgreSQL:
                    services.RegisterNpgSqlDbContexts<TIdentityDbContext, TConfigurationDbContext, TPersistedGrantDbContext, TDataProtectionDbContext>(identityConnectionString, configurationConnectionString, persistedGrantsConnectionString, dataProtectionConnectionString);
                    break;
                case DatabaseProviderType.MySql:
                    services.RegisterMySqlDbContexts<TIdentityDbContext, TConfigurationDbContext, TPersistedGrantDbContext, TDataProtectionDbContext>(identityConnectionString, configurationConnectionString, persistedGrantsConnectionString, dataProtectionConnectionString);
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(databaseProvider.ProviderType), $@"The value needs to be one of {string.Join(", ", Enum.GetNames(typeof(DatabaseProviderType)))}.");
            }
        }


        /// <summary>
        /// Register InMemory DbContexts for IdentityServer ConfigurationStore, PersistedGrants, Identity and DataProtection
        /// Configure the connection strings in AppSettings.json
        /// </summary>
        /// <typeparam name="TConfigurationDbContext"></typeparam>
        /// <typeparam name="TPersistedGrantDbContext"></typeparam>
        /// <typeparam name="TIdentityDbContext"></typeparam>
        /// <param name="services"></param>
        public static void RegisterDbContextsStaging<TIdentityDbContext, TConfigurationDbContext, TPersistedGrantDbContext, TDataProtectionDbContext>(
            this IServiceCollection services)
            where TIdentityDbContext : DbContext
            where TPersistedGrantDbContext : DbContext, IAdminPersistedGrantDbContext
            where TConfigurationDbContext : DbContext, IAdminConfigurationDbContext
            where TDataProtectionDbContext : DbContext, IDataProtectionKeyContext
        {
            var identityDatabaseName = Guid.NewGuid().ToString();
            services.AddDbContext<TIdentityDbContext>(optionsBuilder => optionsBuilder.UseInMemoryDatabase(identityDatabaseName));

            var configurationDatabaseName = Guid.NewGuid().ToString();
            var operationalDatabaseName = Guid.NewGuid().ToString();
            var dataProtectionDatabaseName = Guid.NewGuid().ToString();

            services.AddConfigurationDbContext<TConfigurationDbContext>(options =>
            {
                options.ConfigureDbContext = b => b.UseInMemoryDatabase(configurationDatabaseName);
            });

            services.AddOperationalDbContext<TPersistedGrantDbContext>(options =>
            {
                options.ConfigureDbContext = b => b.UseInMemoryDatabase(operationalDatabaseName);
            });

            services.AddDbContext<TDataProtectionDbContext>(options =>
            {
                options.UseInMemoryDatabase(dataProtectionDatabaseName);
            });
        }

        /// <summary>
        /// Add services for authentication, including Identity model, Duende IdentityServer and external providers
        /// </summary>
        /// <typeparam name="TIdentityDbContext">DbContext for Identity</typeparam>
        /// <typeparam name="TUserIdentity">User Identity class</typeparam>
        /// <typeparam name="TUserIdentityRole">User Identity Role class</typeparam>
        /// <param name="services"></param>
        /// <param name="configuration"></param>
        private static void AddAuthenticationServices<TIdentityDbContext, TUserIdentity, TUserIdentityRole>(this IServiceCollection services, IConfiguration configuration) where TIdentityDbContext : DbContext
            where TUserIdentity : class
            where TUserIdentityRole : class
        {
            var loginConfiguration = GetLoginConfiguration(configuration);
            var registrationConfiguration = GetRegistrationConfiguration(configuration);
            var identityOptions = configuration.GetSection(nameof(IdentityOptions)).Get<IdentityOptions>();

            services
                .AddSingleton(registrationConfiguration)
                .AddSingleton(loginConfiguration)
                .AddSingleton(identityOptions)
                .AddScoped<ApplicationSignInManager<TUserIdentity>>()
                .AddScoped<UserResolver<TUserIdentity>>()
                .AddIdentity<TUserIdentity, TUserIdentityRole>(options => configuration.GetSection(nameof(IdentityOptions)).Bind(options))
                .AddEntityFrameworkStores<TIdentityDbContext>()
                .AddDefaultTokenProviders();

            services.Configure<CookiePolicyOptions>(options =>
            {
                options.MinimumSameSitePolicy = SameSiteMode.Unspecified;
                options.Secure = CookieSecurePolicy.SameAsRequest;
                options.OnAppendCookie = cookieContext =>
                    AuthenticationHelpers.CheckSameSite(cookieContext.Context, cookieContext.CookieOptions);
                options.OnDeleteCookie = cookieContext =>
                    AuthenticationHelpers.CheckSameSite(cookieContext.Context, cookieContext.CookieOptions);
            });


            services.Configure<IISOptions>(iis =>
            {
                iis.AuthenticationDisplayName = "Windows";
                iis.AutomaticAuthentication = false;
            });

            var authenticationBuilder = services.AddAuthentication();

            AddExternalProviders(authenticationBuilder, configuration);
        }

        public static void ConfigureAuthentication(this WebApplicationBuilder builder)
        {
            builder.Services.AddAuthenticationServices<TenantIdentityDbContext, UserIdentity, UserIdentityRole>(builder.Configuration);
            builder.Services.AddIdentityServer<IdentityServerConfigurationDbContext, IdentityServerPersistedGrantDbContext, UserIdentity>(builder.Configuration);

            builder.Services.AddDistributedCacheTicketStore();
        }
        /// <summary>
        /// Get configuration for login
        /// </summary>
        /// <param name="configuration"></param>
        /// <returns></returns>
        private static LoginConfiguration GetLoginConfiguration(IConfiguration configuration)
        {
            var loginConfiguration = configuration.GetSection(nameof(LoginConfiguration)).Get<LoginConfiguration>();

            // Cannot load configuration - use default configuration values
            if (loginConfiguration == null)
            {
                return new LoginConfiguration();
            }

            return loginConfiguration;
        }

        /// <summary>
        /// Get configuration for registration
        /// </summary>
        /// <param name="configuration"></param>
        /// <returns></returns>
        private static RegisterConfiguration GetRegistrationConfiguration(IConfiguration configuration)
        {
            var registerConfiguration = configuration.GetSection(nameof(RegisterConfiguration)).Get<RegisterConfiguration>();

            // Cannot load configuration - use default configuration values
            if (registerConfiguration == null)
            {
                return new RegisterConfiguration();
            }

            return registerConfiguration;
        }

        /// <summary>
        /// Add configuration for Duende IdentityServer
        /// </summary>
        /// <typeparam name="TUserIdentity"></typeparam>
        /// <typeparam name="TConfigurationDbContext"></typeparam>
        /// <typeparam name="TPersistedGrantDbContext"></typeparam>
        /// <param name="services"></param>
        /// <param name="configuration"></param>
        private static IIdentityServerBuilder AddIdentityServer<TConfigurationDbContext, TPersistedGrantDbContext, TUserIdentity>(
            this IServiceCollection services,
            IConfiguration configuration)
            where TPersistedGrantDbContext : DbContext, IAdminPersistedGrantDbContext
            where TConfigurationDbContext : DbContext, IAdminConfigurationDbContext
            where TUserIdentity : class
        {
            var configurationSection = configuration.GetSection(nameof(IdentityServerOptions));

            var identityServerOptions = configurationSection.Get<IdentityServerOptions>();

            var builder = services.AddIdentityServer(options =>
                {
                    configurationSection.Bind(options);

                    options.DynamicProviders.SignInScheme = IdentityConstants.ExternalScheme;
                    options.DynamicProviders.SignOutScheme = IdentityConstants.ApplicationScheme;

                })
                .AddConfigurationStore<TConfigurationDbContext>()
                .AddOperationalStore<TPersistedGrantDbContext>()
                .AddAspNetIdentity<TUserIdentity>()
                .AddRedirectUriValidator<TenantRedirectUriValidator>();

            services.ConfigureOptions<OpenIdClaimsMappingConfig>();

            if (!identityServerOptions.KeyManagement.Enabled)
            {
                builder.AddCustomSigningCredential(configuration);
                builder.AddCustomValidationKey(configuration);
            }

            builder.AddExtensionGrantValidator<DelegationGrantValidator>();

            return builder;
        }

        /// <summary>
        /// Add external providers
        /// </summary>
        /// <param name="authenticationBuilder"></param>
        /// <param name="configuration"></param>
        private static void AddExternalProviders(AuthenticationBuilder authenticationBuilder,
            IConfiguration configuration)
        {
            var externalProviderConfiguration = configuration.GetSection(nameof(ExternalProvidersConfiguration)).Get<ExternalProvidersConfiguration>();

        }

        /// <summary>
        /// Register middleware for localization
        /// </summary>
        /// <param name="app"></param>
        public static void UseMvcLocalizationServices(this IApplicationBuilder app)
        {
            var options = app.ApplicationServices.GetService<IOptions<RequestLocalizationOptions>>();
            app.UseRequestLocalization(options.Value);
        }

        /// <summary>
        /// Add authorization policies
        /// </summary>
        /// <param name="services"></param>
        public static void ConfigureAuthorization(this WebApplicationBuilder builder)
        {
            var rootConfiguration = CreateRootConfiguration(builder);
            builder.Services.AddAuthorization(options =>
            {
                options.AddPolicy(AuthorizationConsts.AdministrationPolicy,
                    policy => policy.RequireRole(rootConfiguration.AdminConfiguration.AdministrationRole));
            });
        }

        public static void AddIdSHealthChecks<TConfigurationDbContext, TPersistedGrantDbContext, TIdentityDbContext>(this WebApplicationBuilder builder)
            where TConfigurationDbContext : DbContext, IAdminConfigurationDbContext
            where TPersistedGrantDbContext : DbContext, IAdminPersistedGrantDbContext
            where TIdentityDbContext : DbContext
        {
            var services = builder.Services;
            var configuration = builder.Configuration;
            var configurationDbConnectionString = configuration.GetConnectionString(ConfigurationConsts.ConfigurationDbConnectionStringKey);
            var persistedGrantsDbConnectionString = configuration.GetConnectionString(ConfigurationConsts.PersistedGrantDbConnectionStringKey);
            var identityDbConnectionString = configuration.GetConnectionString(ConfigurationConsts.IdentityDbConnectionStringKey);
            var dataProtectionDbConnectionString = configuration.GetConnectionString(ConfigurationConsts.DataProtectionDbConnectionStringKey);

            var healthChecksBuilder = services.AddHealthChecks()
                .AddDbContextCheck<TConfigurationDbContext>("ConfigurationDbContext")
                .AddDbContextCheck<TPersistedGrantDbContext>("PersistedGrantsDbContext")
                .AddDbContextCheck<TIdentityDbContext>("IdentityDbContext");

            var serviceProvider = services.BuildServiceProvider();
            var scopeFactory = serviceProvider.GetRequiredService<IServiceScopeFactory>();
            using (var scope = scopeFactory.CreateScope())
            {
                var configurationTableName = DbContextHelpers.GetEntityTable<TConfigurationDbContext>(scope.ServiceProvider);
                var persistedGrantTableName = DbContextHelpers.GetEntityTable<TPersistedGrantDbContext>(scope.ServiceProvider);
                var identityTableName = DbContextHelpers.GetEntityTable<TIdentityDbContext>(scope.ServiceProvider);

                var databaseProvider = configuration.GetSection(nameof(DatabaseProviderConfiguration)).Get<DatabaseProviderConfiguration>();
                switch (databaseProvider.ProviderType)
                {
                    case DatabaseProviderType.SqlServer:
                        healthChecksBuilder
                            .AddSqlServer(configurationDbConnectionString, name: "ConfigurationDb",
                                healthQuery: $"SELECT TOP 1 * FROM dbo.[{configurationTableName}]")
                            .AddSqlServer(persistedGrantsDbConnectionString, name: "PersistentGrantsDb",
                                healthQuery: $"SELECT TOP 1 * FROM dbo.[{persistedGrantTableName}]")
                            .AddSqlServer(identityDbConnectionString, name: "IdentityDb",
                                healthQuery: $"SELECT TOP 1 * FROM dbo.[{identityTableName}]");

                        break;
                    case DatabaseProviderType.PostgreSQL:
                        healthChecksBuilder
                            .AddNpgSql(configurationDbConnectionString, name: "ConfigurationDb",
                                healthQuery: $"SELECT * FROM \"{configurationTableName}\" LIMIT 1")
                            .AddNpgSql(persistedGrantsDbConnectionString, name: "PersistentGrantsDb",
                                healthQuery: $"SELECT * FROM \"{persistedGrantTableName}\" LIMIT 1")
                            .AddNpgSql(identityDbConnectionString, name: "IdentityDb",
                                healthQuery: $"SELECT * FROM \"{identityTableName}\" LIMIT 1");
                        break;
                    case DatabaseProviderType.MySql:
                        healthChecksBuilder
                            .AddMySql(configurationDbConnectionString, name: "ConfigurationDb")
                            .AddMySql(persistedGrantsDbConnectionString, name: "PersistentGrantsDb")
                            .AddMySql(identityDbConnectionString, name: "IdentityDb");
                        break;
                    default:
                        throw new NotImplementedException($"Health checks not defined for database provider {databaseProvider.ProviderType}");
                }
            }
        }

        public static void RegisterHstsOptions(this WebApplicationBuilder builder)
        {
            builder.Services.AddHsts(options =>
            {
                options.Preload = true;
                options.IncludeSubDomains = true;
                options.MaxAge = TimeSpan.FromDays(365);
            });
        }

        public static void AddRootConfiguration(this WebApplicationBuilder builder)
        {
            var rootConfiguration = CreateRootConfiguration(builder);
            builder.Services.AddSingleton(rootConfiguration);
        }

        private static IRootConfiguration CreateRootConfiguration(WebApplicationBuilder builder)
        {
            var rootConfiguration = new RootConfiguration();
            builder.Configuration.GetSection(ConfigurationConsts.AdminConfigurationKey).Bind(rootConfiguration.AdminConfiguration);
            builder.Configuration.GetSection(ConfigurationConsts.RegisterConfigurationKey).Bind(rootConfiguration.RegisterConfiguration);
            return rootConfiguration;
        }


        public static void ConfigureMultiTenant(this WebApplicationBuilder builder)
        {
            builder.Services
            .AddMultiTenant(options =>
            {
                options.Events.OnTenantResolved = async context =>
                {
                    if (context.TenantInfo != null)
                    {
                        var tenantInfo = context.TenantInfo;
                        var httpContext = (context.Context as HttpContext);
                        //httpContext?.Response.Cookies.Delete(".AspNetCore.Identity.Application");
                        foreach (var cookie in httpContext?.Request.Cookies)
                        {
                            if (cookie.Key.StartsWith(".AspNetCore.Antiforgery", StringComparison.OrdinalIgnoreCase))
                            {
                                httpContext?.Response.Cookies.Delete(cookie.Key, new CookieOptions { Path = "/" });
                            }
                        }
                    }
                };
            })
            .WithBasePathStrategy(options => options.RebaseAspNetCorePathBase = true)
            .ConfigureTenantEFDirectly(builder.Configuration, options =>
            {
                options.DatabaseProvider = "PostgreSQL";
                options.ConnectionName = "TenantDbConnection";
                options.Schema = "App";
            }, builder.Environment.EnvironmentName)
            .WithPerTenantAuthenticationCore()
            .WithPerTenantAuthenticationConventions(crossTenantAuthorize: (authTenant, currentTenant, principal) =>

                authTenant == null // root tenant
                && (principal?.Identity?.IsAuthenticated ?? false) // authenticated
                && principal.IsInRole("admin"))
            .WithRemoteAuthenticationCallbackStrategy()
            ;

        }

        static FinbuckleMultiTenantBuilder<TTenantInfo> WithPerTenantAuthenticationConventions<TTenantInfo>(
            this FinbuckleMultiTenantBuilder<TTenantInfo> builder,
            CrossTenantAuthorize? crossTenantAuthorize
            )
            where TTenantInfo : class, IDynamic, ITenantInfo, new()
        {
            // Set events to set and validate tenant for each cookie based authentication principal.
            builder.Services.ConfigureAll<CookieAuthenticationOptions>(options =>
            {
                // Validate that claimed tenant matches current tenant.
                var origOnValidatePrincipal = options.Events.OnValidatePrincipal;
                options.Events.OnValidatePrincipal = async context =>
                {
                    // Skip if bypass set (e.g. ClaimsStrategy in effect)
                    if (context.HttpContext.Items.Keys.Contains(
                            $"{Constants.TenantToken}__bypass_validate_principal__"))
                        return;

                    var currentTenant = context.HttpContext.GetMultiTenantContext<TTenantInfo>()?.TenantInfo
                        ?.Identifier;
                    string? authTenant = null;
                    if (context.Properties.Items.ContainsKey(Constants.TenantToken))
                    {
                        authTenant = context.Properties.Items[Constants.TenantToken];
                    }
                    else
                    {
                        var loggerFactory = context.HttpContext.RequestServices.GetService<ILoggerFactory>();
                        loggerFactory?.CreateLogger<FinbuckleMultiTenantBuilder<TTenantInfo>>()
                            .LogInformation("No tenant found in authentication properties.");
                    }

                    // Does the current tenant match the auth property tenant?
                    if (!string.Equals(currentTenant, authTenant, StringComparison.OrdinalIgnoreCase)
                        && (crossTenantAuthorize == null
                            || !crossTenantAuthorize(authTenant, currentTenant, context.Principal))
                    )
                    {
                        context.RejectPrincipal();
                    }

                    await origOnValidatePrincipal(context);
                };

            });

            // Set per-tenant cookie options by convention.
            builder.WithPerTenantOptions<CookieAuthenticationOptions>((options, tc) =>
            {
                if (GetPropertyWithValidValue(tc, "CookieLoginPath") is string loginPath)
                    options.LoginPath = loginPath.Replace(Constants.TenantToken, tc.Identifier);

                if (GetPropertyWithValidValue(tc, "CookieLogoutPath") is string logoutPath)
                    options.LogoutPath = logoutPath.Replace(Constants.TenantToken, tc.Identifier);

                if (GetPropertyWithValidValue(tc, "CookieAccessDeniedPath") is string accessDeniedPath)
                    options.AccessDeniedPath = accessDeniedPath.Replace(Constants.TenantToken, tc.Identifier);
            });

            // Set per-tenant OpenIdConnect options by convention.
            builder.WithPerTenantOptions<OpenIdConnectOptions>((options, tc) =>
            {
                if (GetPropertyWithValidValue(tc, "OpenIdConnectAuthority") is string authority)
                    options.Authority = authority.Replace(Constants.TenantToken, tc.Identifier);

                if (GetPropertyWithValidValue(tc, "OpenIdConnectClientId") is string clientId)
                    options.ClientId = clientId.Replace(Constants.TenantToken, tc.Identifier);

                if (GetPropertyWithValidValue(tc, "OpenIdConnectClientSecret") is string clientSecret)
                    options.ClientSecret = clientSecret.Replace(Constants.TenantToken, tc.Identifier);
            });

            builder.WithPerTenantOptions<Microsoft.AspNetCore.Authentication.AuthenticationOptions>((options, tc) =>
            {
                if (GetPropertyWithValidValue(tc, "ChallengeScheme") is string challengeScheme)
                    options.DefaultChallengeScheme = challengeScheme;
            });

            return builder;

            string? GetPropertyWithValidValue(TTenantInfo entity, string propertyName)
            {
                return (entity as IDynamic)?.GetProperty<string?>(() => default, propertyName);
            }
        }

        public static void ConfigureDistributedCache(this WebApplicationBuilder builder)
        {
            builder.Services.AddStackExchangeRedisCache(options =>
            {
                options.Configuration = builder.Configuration.GetConnectionString("Redis");
                options.InstanceName = "sts-identity";
            });
        }

        public static void ConfigureDataProtection(this WebApplicationBuilder builder)
        {
            var redis = ConnectionMultiplexer.Connect(builder.Configuration.GetConnectionString("Redis"));

            builder.Services
                .AddDataProtection().SetApplicationName(SecretName)
                .PersistKeysToStackExchangeRedis(redis, "DataProtection-Keys");
        }

    }

    /// <summary>
    /// Validate tenant redirect uri with pattern https://app.example.com/__tenant__/signin-oidc
    /// </summary>
    internal class TenantRedirectUriValidator : IRedirectUriValidator
    {
        private readonly ITenantInfo? _tenantInfo;
        public TenantRedirectUriValidator(ITenantInfo? tenantInfo = null)
        {
            _tenantInfo = tenantInfo;
        }
        public Task<bool> IsRedirectUriValidAsync(string requestedUri, Client client)
        {

            if (_tenantInfo?.Identifier != null)
            {
                return Task.FromResult(client.RedirectUris
                    .Any(uri => uri.Replace(Constants.TenantToken, _tenantInfo.Identifier) == requestedUri));

            }
            return Task.FromResult(client.RedirectUris.Contains(requestedUri));
        }
        public Task<bool> IsPostLogoutRedirectUriValidAsync(string requestedUri, Client client)
        {
            if (_tenantInfo?.Identifier != null)
            {
                return Task.FromResult(client.PostLogoutRedirectUris
                    .Any(uri => uri.Replace(Constants.TenantToken, _tenantInfo.Identifier) == requestedUri));

            }
            return Task.FromResult(client.PostLogoutRedirectUris.Contains(requestedUri));
        }
    }

}








