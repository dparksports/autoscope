namespace AutoScope.Models
{
    public interface IResolvableHost
    {
        string RemoteIp { get; }
        string Hostname { get; set; }
    }
}
