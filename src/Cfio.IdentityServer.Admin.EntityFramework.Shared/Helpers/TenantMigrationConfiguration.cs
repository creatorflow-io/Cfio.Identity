namespace Cfio.IdentityServer.Admin.EntityFramework.Shared.Helpers
{
    public class TenantMigrationConfiguration
    {
        public string Id { get; set; }
        public string Identifier { get; set; }
        public string Name { get; set; }
        public string ConnectionString { get; set; }
        public string AdminEmail { get; set; }
    }
}
