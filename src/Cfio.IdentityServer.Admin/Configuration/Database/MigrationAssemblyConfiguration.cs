// Copyright (c) Jan Škoruba. All Rights Reserved.
// Licensed under the Apache License, Version 2.0.

using Skoruba.Duende.IdentityServer.Admin.EntityFramework.Configuration.Configuration;
using System;
using System.Reflection;
using PostgreSQLMigrationAssembly = Cfio.IdentityServer.Admin.EntityFramework.PostgreSQL.Helpers.MigrationAssembly;
using SqlMigrationAssembly = Cfio.IdentityServer.Admin.EntityFramework.SqlServer.Helpers.MigrationAssembly;

namespace Cfio.IdentityServer.Admin.Configuration.Database
{
    public static class MigrationAssemblyConfiguration
    {
        public static string GetMigrationAssemblyByProvider(DatabaseProviderConfiguration databaseProvider)
        {
            return databaseProvider.ProviderType switch
            {
                DatabaseProviderType.SqlServer => typeof(SqlMigrationAssembly).GetTypeInfo().Assembly.GetName().Name,
                DatabaseProviderType.PostgreSQL => typeof(PostgreSQLMigrationAssembly).GetTypeInfo()
                    .Assembly.GetName()
                    .Name,
                _ => throw new ArgumentOutOfRangeException()
            };
        }
    }
}







